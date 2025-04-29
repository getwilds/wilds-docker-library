#!/usr/bin/env python
# -*-coding:utf-8 -*-
"""
@File    :   combine_star_counts.py
@Time    :   2025/04/24
@Author  :   Taylor Firman
@Version :   0.1.0
@Contact :   tfirman@fredhutch.org
@Desc    :   Combine individual STAR counts into a single matrix for DESeq2
"""

import pandas as pd
import os
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Combine STAR count matrices')
    parser.add_argument('--input', nargs='+', required=True, help='Input gene count files from STAR')
    parser.add_argument('--output', default='combined_counts_matrix.txt', help='Output combined matrix file')
    parser.add_argument('--count_column', type=int, default=2, 
                        help='Which column to use (2=unstranded, 3=stranded forward, 4=stranded reverse)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    count_files = args.input
    count_column = args.count_column
    
    # Extract sample names from file paths
    sample_names = []
    for file_path in count_files:
        # Extract the base filename from the path
        basename = os.path.basename(file_path)
        # Extract the sample name before the first dot
        sample_name = basename.split('.')[0]
        sample_names.append(sample_name)
    
    print(f"Processing {len(count_files)} count files...")
    print(f"Sample names extracted: {sample_names}")
    
    # Function to read STAR gene count file
    def read_star_counts(file_path, sample_name, count_col):
        # Skip the first 4 lines (summary statistics)
        df = pd.read_csv(file_path, sep='\t', skiprows=4, header=None)
        
        # Select only gene ID column and the requested count column
        df = df.iloc[:, [0, count_col-1]]
        
        # Name the columns
        df.columns = ['gene_id', sample_name]
        
        return df
    
    # Read the first file to get the gene list
    print(f"Reading first file: {os.path.basename(count_files[0])}")
    combined = read_star_counts(count_files[0], sample_names[0], count_column)
    
    # Add the rest of the samples
    if len(count_files) > 1:
        for i in range(1, len(count_files)):
            print(f"Reading file {i+1}/{len(count_files)}: {os.path.basename(count_files[i])}")
            sample_counts = read_star_counts(count_files[i], sample_names[i], count_column)
            combined = pd.merge(combined, sample_counts, on='gene_id')
    
    # Write out the combined matrix
    print(f"Writing combined matrix to {args.output}...")
    combined.to_csv(args.output, sep='\t', index=False)
    
    # Print summary
    print(f"Combined {len(sample_names)} samples into a single count matrix")
    print(f"Total genes: {len(combined)}")
    print("Output files:")
    print(f"  - {args.output} (main counts matrix)")

if __name__ == "__main__":
    main()
