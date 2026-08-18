cat("\n")
cat("=============================================\n")
cat("OHDSI / HADES Databricks Image Validation\n")
cat("=============================================\n\n")


# ------------------------------------------------------------
# R
# ------------------------------------------------------------

cat("R Version:\n")
cat(R.version.string, "\n")
cat("Library paths:\n")
cat(paste0("  ", .libPaths(), collapse = "\n"), "\n\n")


# ------------------------------------------------------------
# Java / rJava
# ------------------------------------------------------------

cat("Testing Java integration...\n")

if (!requireNamespace("rJava", quietly = TRUE)) {
  stop("rJava is not installed")
}

library(rJava)

.jinit()

java_version <- .jcall(
  "java/lang/System",
  "S",
  "getProperty",
  "java.version"
)

cat("Java version:", java_version, "\n\n")


# ------------------------------------------------------------
# Core packages
#
# requireNamespace() loads the namespace, so this also proves each
# package's compiled code links against the libraries present in the
# image -- a package can install cleanly and still fail to load.
# ------------------------------------------------------------

packages <- c(
  # foundations
  "DatabaseConnector",
  "SqlRender",
  "ParallelLogger",
  "Andromeda",
  "Cyclops",
  "duckdb",
  "V8",
  "CirceR",
  "Eunomia",

  # analytics
  "Achilles",
  "DataQualityDashboard",
  "CohortGenerator",
  "CohortDiagnostics",
  "FeatureExtraction",
  "PatientLevelPrediction",
  "CohortMethod",
  "SelfControlledCaseSeries",
  "Characterization",
  "ResultModelManager",

  # packages installed from github.com/ohdsi
  "Capr",
  "Strategus",
  "Hades"
)


cat("Checking OHDSI packages:\n\n")


for (pkg in packages) {

  if (!requireNamespace(pkg, quietly = TRUE)) {

    stop(
      sprintf(
        "Required package missing: %s",
        pkg
      )
    )
  }

  version <- as.character(
    packageVersion(pkg)
  )

  cat(
    sprintf(
      "%-30s %s\n",
      pkg,
      version
    )
  )
}


cat("\n")
cat("=============================================\n")
cat("OHDSI / HADES validation PASSED\n")
cat("=============================================\n")