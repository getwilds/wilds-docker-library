#!/usr/bin/env Rscript

# Generate DESeq2 test count matrices and metadata using the pasilla Bioconductor dataset
# Author: WILDS Team
# Description: Creates count matrix, sample metadata, and gene info files for testing

# Load required libraries
suppressPackageStartupMessages({
    library(optparse)
    library(pasilla)
    library(DESeq2)
})

# Define command line options
option_list <- list(
    make_option(c("-n", "--nsamples"), type = "integer", default = 7,
                help = "Number of samples to include (default: 7, max: 7 for pasilla dataset)"),
    make_option(c("-g", "--ngenes"), type = "integer", default = 10000,
                help = "Approximate number of genes to include (will select top expressed genes)"),
    make_option(c("-c", "--condition"), type = "character", default = "condition",
                help = "Name for the condition column in metadata"),
    make_option(c("-p", "--prefix"), type = "character", default = "pasilla",
                help = "Prefix for output files")
)

# Parse command line arguments
opt_parser <- OptionParser(option_list = option_list,
                          description = "Generate DESeq2 test data from pasilla dataset")
opt <- parse_args(opt_parser)

# Main execution
tryCatch({
    cat("=== Generating pasilla test data ===\n")
    cat("Parameters:\n")
    cat("  Samples:", opt$nsamples, "\n")
    cat("  Genes:", opt$ngenes, "\n")
    cat("  Condition column:", opt$condition, "\n")
    cat("  Output prefix:", opt$prefix, "\n\n")
    
    # Get the actual pasilla data files
    count_file <- system.file("extdata", "pasilla_gene_counts.tsv", package = "pasilla")
    sample_file <- system.file("extdata", "pasilla_sample_annotation.csv", package = "pasilla")
    
    cat("Loading pasilla data from:\n")
    cat("Count file:", count_file, "\n")
    cat("Sample file:", sample_file, "\n\n")
    
    # Read the count matrix and sample data
    count_data <- read.table(count_file, header = TRUE, row.names = 1, sep = "\t")
    sample_data <- read.csv(sample_file, header = TRUE, row.names = 1)
    
    cat("Original data dimensions:\n")
    cat("Genes:", nrow(count_data), "\n")
    cat("Samples:", ncol(count_data), "\n\n")
    
    # Remove 'fb' suffix from sample metadata row names to match count data
    rownames(sample_data) <- gsub("fb$", "", rownames(sample_data))

    # Make sure sample names match between count data and metadata
    common_samples <- intersect(colnames(count_data), rownames(sample_data))
    count_data <- count_data[, common_samples]
    sample_data <- sample_data[common_samples, ]
    
    # Limit to requested number of samples
    n_samples_requested <- opt$nsamples
    if (n_samples_requested > ncol(count_data)) {
        n_samples_requested <- ncol(count_data)
        cat("Warning: Requested", opt$nsamples, "samples, but only", ncol(count_data), "available\n")
    }
    
    # Select samples (ensure we have both conditions represented)
    untreated_samples <- rownames(sample_data)[sample_data$condition == "untreated"]
    treated_samples <- rownames(sample_data)[sample_data$condition == "treated"]
    
    # Take roughly equal numbers from each condition
    n_untreated <- ceiling(n_samples_requested / 2)
    n_treated <- n_samples_requested - n_untreated
    
    # Adjust if we don't have enough samples of one type
    if (n_untreated > length(untreated_samples)) {
        n_untreated <- length(untreated_samples)
        n_treated <- n_samples_requested - n_untreated
    }
    if (n_treated > length(treated_samples)) {
        n_treated <- length(treated_samples)
        n_untreated <- n_samples_requested - n_treated
    }
    
    selected_samples <- c(
        untreated_samples[1:n_untreated],
        treated_samples[1:n_treated]
    )
    
    # Subset data
    count_data <- count_data[, selected_samples]
    sample_data <- sample_data[selected_samples, ]
    
    # Select top expressed genes
    n_genes_requested <- opt$ngenes
    if (n_genes_requested > nrow(count_data)) {
        n_genes_requested <- nrow(count_data)
        cat("Warning: Requested", opt$ngenes, "genes, but only", nrow(count_data), "available\n")
    }
    
    # Calculate mean counts per gene and select top expressed
    gene_means <- rowMeans(count_data)
    top_genes <- order(gene_means, decreasing = TRUE)[1:n_genes_requested]
    
    count_data <- count_data[top_genes, ]
    
    # Create clean sample metadata
    metadata <- data.frame(
        sample_name = colnames(count_data),
        condition = as.character(sample_data$condition),
        type = as.character(sample_data$type),
        stringsAsFactors = FALSE
    )
    
    # Rename condition column if requested
    condition_col_name <- opt$condition
    if (condition_col_name != "condition") {
        names(metadata)[names(metadata) == "condition"] <- condition_col_name
    }
    
    # Generate output filenames
    counts_file <- paste0(opt$prefix, "_counts_matrix.txt")
    metadata_file <- paste0(opt$prefix, "_sample_metadata.txt")
    gene_info_file <- paste0(opt$prefix, "_gene_info.txt")
    
    # Write count matrix (genes as rows, samples as columns)
    # Add gene names as first column
    count_output <- cbind(
        gene_id = rownames(count_data),
        as.data.frame(count_data)
    )
    write.table(count_output, 
                file = counts_file, 
                sep = "\t", 
                row.names = FALSE, 
                col.names = TRUE,
                quote = FALSE)
    
    # Write sample metadata
    write.table(metadata, 
                file = metadata_file, 
                sep = "\t", 
                row.names = FALSE, 
                col.names = TRUE,
                quote = FALSE)
    
    # Write gene information (simpler since we don't have detailed gene data)
    gene_info <- data.frame(
        gene_id = rownames(count_data),
        gene_name = rownames(count_data),  # Use gene ID as name since we don't have symbols
        stringsAsFactors = FALSE
    )
    write.table(gene_info, 
                file = gene_info_file, 
                sep = "\t", 
                row.names = FALSE, 
                col.names = TRUE,
                quote = FALSE)
    
    # Print summary
    cat("\n=== Generated pasilla test data ===\n")
    cat("Files created:\n")
    cat("  Count matrix:", counts_file, "\n")
    cat("  Sample metadata:", metadata_file, "\n")
    cat("  Gene info:", gene_info_file, "\n\n")
    cat("Data summary:\n")
    cat("  Samples:", ncol(count_data), "\n")
    cat("  Genes:", nrow(count_data), "\n")
    cat("  Conditions:", paste(unique(metadata[[condition_col_name]]), collapse = ", "), "\n")
    cat("\nScript completed successfully!\n")

}, error = function(e) {
    cat("Error occurred during execution:\n")
    cat(conditionMessage(e), "\n")
    quit(status = 1)
})
