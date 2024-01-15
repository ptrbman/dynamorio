import os
import zipfile
import shutil


l1_data_cache_sizes = ["1k", "2k", "8k", "128k", "256k", "512k"]
l1_inst_cache_sizes = ["1k", "2k", "8k"]
ll_cache_sizes = ["1k", "2k", "8k", "128k", "256k", "512k"]
matrix_sizes = ["10", "20", "50", "80", "100"]

total_runs = len(l1_data_cache_sizes)*len(l1_inst_cache_sizes)*len(ll_cache_sizes)*len(matrix_sizes)
counter = 0

# Remove the contents of the directory if it's not empty
if os.path.exists("./15012024/"):
    shutil.rmtree("./15012024/")
os.mkdir("./15012024/")
for l1_data_cache_size in l1_data_cache_sizes:
    for l1_inst_cache_size in l1_inst_cache_sizes:
        for ll_cache_size in ll_cache_sizes:
            for matrix_size in matrix_sizes:
                
                long_name = f"l1d_{l1_data_cache_size}_l1i_{l1_inst_cache_size}_ll_{ll_cache_size}_matmult_{matrix_size}"
                os.system(f"mkdir ./15012024/{long_name}.dir")
                os.system(
                    f"./build_no_limit/bin64/drrun -t drcachesim -offline \
                          -outdir ./15012024/{long_name}.dir -- ./../application/matmult {matrix_size}"
                )
                print(f"Done {counter}/{total_runs} initial run.")
                counter+=1

counter = 0
for l1_data_cache_size in l1_data_cache_sizes:
    for l1_inst_cache_size in l1_inst_cache_sizes:
        for ll_cache_size in ll_cache_sizes:
            for matrix_size in matrix_sizes:
                long_name = f"l1d_{l1_data_cache_size}_l1i_{l1_inst_cache_size}_ll_{ll_cache_size}_matmult_{matrix_size}"
                generated_file = f"./15012024/{long_name}.txt"
                os.system(
                    f"./build_no_limit/bin64/drrun -t drcachesim -simulator_type missing_instructions \
                          -L1D_size {l1_data_cache_size} -L1I_size {l1_inst_cache_size} -LL_size {ll_cache_size} \
                          -indir ./15012024/{long_name}.dir/* 2>&1 | tee {generated_file}"
                )
                
                # Compress the generated file
                with zipfile.ZipFile(f"{generated_file}.zip", 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(generated_file, os.path.basename(generated_file))

                # Remove the original file if needed
                os.remove(generated_file)
                print(f"Done {counter}/{total_runs} disassembly run.")
                counter+=1
