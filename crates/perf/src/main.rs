use std::{
    env,
    io::Write,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{command, Parser};
use sp1_cuda::SP1CudaProver;
use sp1_prover::HashableKey;
use sp1_prover::{components::CpuProverComponents, ProverMode};
use sp1_sdk::{self, block_on, NetworkProverV2, Prover, SP1Context, SP1Prover, SP1Stdin};
use sp1_stark::SP1ProverOpts;
use test_artifacts::VERIFY_PROOF_ELF;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct PerfArgs {
    /// The program to evaluate.
    #[arg(short, long)]
    pub program: String,

    /// The input to the program being evaluated.
    #[arg(short, long)]
    pub stdin: String,

    /// The prover mode to use.
    ///
    /// Provide this only in prove mode.
    #[arg(short, long)]
    pub mode: ProverMode,
}

#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
struct PerfResult {
    pub cycles: u64,
    pub execution_duration: Duration,
    pub prove_core_duration: Duration,
    pub verify_core_duration: Duration,
    pub compress_duration: Duration,
    pub verify_compressed_duration: Duration,
    pub shrink_duration: Duration,
    pub verify_shrink_duration: Duration,
    pub wrap_duration: Duration,
    pub verify_wrap_duration: Duration,
}

pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, std::time::Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = PerfArgs::parse();

    let elf = std::fs::read(&args.program).expect("failed to read program");
    let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
    let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

    let opts = SP1ProverOpts::auto();

    let prover = SP1Prover::<CpuProverComponents>::new();
    let (_, pk_d, program, vk) = prover.setup(&elf);
    match args.mode {
        ProverMode::Cpu => {
            let context = SP1Context::default();
            let (report, execution_duration) =
                time_operation(|| prover.execute(&elf, &stdin, context.clone()));

            let cycles = report.expect("execution failed").1.total_instruction_count();

            let (core_proof, prove_core_duration) = time_operation(|| {
                prover.prove_core(&pk_d, program, &stdin, opts, context).unwrap()
            });

            let (_, verify_core_duration) =
                time_operation(|| prover.verify(&core_proof.proof, &vk));

            let proofs = stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
            let (compress_proof, compress_duration) =
                time_operation(|| prover.compress(&vk, core_proof.clone(), proofs, opts).unwrap());

            let (_, verify_compressed_duration) =
                time_operation(|| prover.verify_compressed(&compress_proof, &vk));

            let (shrink_proof, shrink_duration) =
                time_operation(|| prover.shrink(compress_proof.clone(), opts).unwrap());

            let (_, verify_shrink_duration) =
                time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

            let (wrapped_bn254_proof, wrap_duration) =
                time_operation(|| prover.wrap_bn254(shrink_proof, opts).unwrap());

            let (_, verify_wrap_duration) =
                time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk));

            // Generate a proof that verifies two deferred proofs from the proof above.
            let (_, pk_verify_proof_d, pk_verify_program, vk_verify_proof) =
                prover.setup(VERIFY_PROOF_ELF);
            let pv = core_proof.public_values.to_vec();

            let mut stdin = SP1Stdin::new();
            let vk_u32 = vk.hash_u32();
            stdin.write::<[u32; 8]>(&vk_u32);
            stdin.write::<Vec<Vec<u8>>>(&vec![pv.clone(), pv.clone()]);
            stdin.write_proof(compress_proof.clone(), vk.vk.clone());
            stdin.write_proof(compress_proof.clone(), vk.vk.clone());

            let context = SP1Context::default();
            let (core_proof, _) = time_operation(|| {
                prover
                    .prove_core(&pk_verify_proof_d, pk_verify_program, &stdin, opts, context)
                    .unwrap()
            });
            let deferred_proofs =
                stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
            let (compress_proof, _) = time_operation(|| {
                prover
                    .compress(&vk_verify_proof, core_proof.clone(), deferred_proofs, opts)
                    .unwrap()
            });
            prover.verify_compressed(&compress_proof, &vk_verify_proof).unwrap();

            let result = PerfResult {
                cycles,
                execution_duration,
                prove_core_duration,
                verify_core_duration,
                compress_duration,
                verify_compressed_duration,
                shrink_duration,
                verify_shrink_duration,
                wrap_duration,
                verify_wrap_duration,
            };

            println!("{:?}", result);
        }
        ProverMode::Cuda => {
            let server = SP1CudaProver::new().expect("failed to initialize CUDA prover");

            let context = SP1Context::default();
            let (report, execution_duration) =
                time_operation(|| prover.execute(&elf, &stdin, context.clone()));

            let cycles = report.expect("execution failed").1.total_instruction_count();

            let (_, _) = time_operation(|| server.setup(&elf).unwrap());

            let (core_proof, prove_core_duration) =
                time_operation(|| server.prove_core(&stdin).unwrap());

            let (_, verify_core_duration) = time_operation(|| {
                prover.verify(&core_proof.proof, &vk).expect("Proof verification failed")
            });

            let proofs = stdin.proofs.into_iter().map(|(proof, _)| proof).collect::<Vec<_>>();
            let (compress_proof, compress_duration) =
                time_operation(|| server.compress(&vk, core_proof, proofs).unwrap());

            let (_, verify_compressed_duration) =
                time_operation(|| prover.verify_compressed(&compress_proof, &vk));

            let (shrink_proof, shrink_duration) =
                time_operation(|| server.shrink(compress_proof).unwrap());

            let (_, verify_shrink_duration) =
                time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

            let (_, wrap_duration) = time_operation(|| server.wrap_bn254(shrink_proof).unwrap());

            // TODO: FIX
            //
            // let (_, verify_wrap_duration) =
            //     time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk));

            let result = PerfResult {
                cycles,
                execution_duration,
                prove_core_duration,
                verify_core_duration,
                compress_duration,
                verify_compressed_duration,
                shrink_duration,
                verify_shrink_duration,
                wrap_duration,
                ..Default::default()
            };

            println!("{:?}", result);
        }
        ProverMode::Network => {
            let private_key = env::var("SP1_PRIVATE_KEY")
                .expect("SP1_PRIVATE_KEY must be set for remote proving");
            let rpc_url = env::var("PROVER_NETWORK_RPC").ok();
            let skip_simulation = true;
            let network_prover = NetworkProverV2::new(&private_key, rpc_url, skip_simulation);

            let (pk, vk) = network_prover.setup(&elf);
            let vk_hash = block_on(network_prover.register_program(&pk.vk, &pk.elf)).unwrap();

            let proof_id = block_on(network_prover.request_proof(
                &vk_hash,
                &stdin,
                sp1_sdk::network_v2::proto::network::ProofMode::Compressed,
                100000000000,
                None,
            ))
            .unwrap();

            let elf_clone = elf.clone();
            let execute_handle = std::thread::spawn(move || {
                let ((_, report), time) = time_operation(|| {
                    prover.execute(&elf_clone, &stdin, Default::default()).unwrap()
                });
                (report.total_instruction_count(), time)
            });

            let start_time = SystemTime::now();
            let (proof, prove_time) = time_operation(|| {
                block_on(network_prover.wait_proof(&proof_id, Some(Duration::from_secs(60 * 60))))
                    .unwrap()
            });

            let (cycles, execute_time) = execute_handle.join().unwrap();

            let (_, verify_time) = time_operation(|| network_prover.verify(&proof, &vk));

            // Write data to csv
            let mut csv_file = std::fs::File::options().append(true).open("network.csv").unwrap();

            // Write header if empty
            if csv_file.metadata().unwrap().len() == 0 {
                csv_file
                .write_all(b"start_time,proof_id,program,cycles,prove_mhz,execute_mhz,execute_time,prove_time,verify_time\n")
                .unwrap();
            }
            csv_file
                .write_all(
                    format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        start_time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        hex::encode(proof_id),
                        args.program,
                        cycles,
                        cycles as f64 / 1_000_000.0 / prove_time.as_secs_f64(),
                        cycles as f64 / 1_000_000.0 / execute_time.as_secs_f64(),
                        execute_time.as_secs_f64(),
                        prove_time.as_secs_f64(),
                        verify_time.as_secs_f64()
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        ProverMode::Mock => unreachable!(),
    };
}
