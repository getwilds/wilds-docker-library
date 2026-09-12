#!/usr/bin/env Rscript

# Restores the pinned HADES lockfile into the R library.
#
# Three things about this lockfile need handling explicitly:
#
# 1. renv applies one deadline to the whole install phase
#    (options(renv.install.timeout), 3600 seconds by default). Nearly 300
#    packages overrun it whenever they are compiled rather than downloaded as
#    binaries, and whatever is still building when the deadline passes is
#    killed with "worker process timed out".
#
# 2. A transactional restore keeps installed packages in a staging library and
#    only migrates them once every package has succeeded, so a single failure
#    throws away the entire run. Installing non-transactionally means progress
#    survives, which is what makes the two passes below worthwhile.
#
# 3. renv learns a GitHub remote's dependencies by fetching its DESCRIPTION
#    over the network. When that lookup fails, the remote looks dependency-free
#    and gets scheduled in the first install wave, so R CMD INSTALL aborts with
#    "dependencies ... are not available". The first pass installs everything
#    from CRAN, so by the time the ohdsi/* remotes are built their dependencies
#    are present regardless of what renv managed to resolve.

lockfile <- Sys.getenv("HADES_LOCKFILE", unset = "/opt/ohdsi/hades/renv.lock")

timeout <- suppressWarnings(as.integer(Sys.getenv("RENV_INSTALL_TIMEOUT")))
if (!is.na(timeout) && timeout > 0L) {
  options(renv.install.timeout = timeout)
}

records <- jsonlite::read_json(lockfile)$Packages
if (!length(records)) {
  stop("no package records found in ", lockfile)
}

from_cran <- vapply(
  records,
  function(record) identical(record$Source, "Repository"),
  logical(1)
)

cran <- names(records)[from_cran]
remotes <- names(records)[!from_cran]


# ------------------------------------------------------------
# Report the settings that decide how long this takes
# ------------------------------------------------------------

cat("Lockfile:        ", lockfile, "\n", sep = "")
cat("Library:         ", .libPaths()[1], "\n", sep = "")
cat("Repositories:    ", paste(getOption("repos"), collapse = ", "), "\n", sep = "")
cat("Install jobs:    ", Sys.getenv("RENV_CONFIG_INSTALL_JOBS", "renv default"), "\n", sep = "")
cat("Install deadline:", getOption("renv.install.timeout", "renv default"), "seconds\n")
cat("GitHub token:    ", if (nzchar(Sys.getenv("GITHUB_PAT"))) "set" else "absent (60 API requests/hour)", "\n", sep = "")
cat("Packages:        ", length(cran), "from CRAN,", length(remotes), "from remotes\n")


# ------------------------------------------------------------
# Pass 1: CRAN packages
#
# Failures are tolerated here; anything left over is the second
# pass's problem. Only the second pass decides the exit status.
# ------------------------------------------------------------

if (length(cran)) {

  cat("\n===== pass 1: CRAN packages =====\n")

  attempt <- try(
    renv::restore(
      lockfile      = lockfile,
      packages      = cran,
      transactional = FALSE,
      prompt        = FALSE
    )
  )

  if (inherits(attempt, "try-error")) {
    cat("\nPass 1 left packages unresolved; continuing to pass 2.\n")
  }

}


# ------------------------------------------------------------
# Pass 2: the full lockfile, including the ohdsi/* remotes
# ------------------------------------------------------------

cat("\n===== pass 2: full lockfile =====\n")

renv::restore(
  lockfile      = lockfile,
  transactional = FALSE,
  prompt        = FALSE
)


# ------------------------------------------------------------
# Verify every record in the lockfile is installed
#
# renv::restore() reports its own failures, but a package can also go
# missing because a dependency was dropped or an install was rolled
# back, so check the library itself rather than trusting the summary.
# ------------------------------------------------------------

cat("\n===== verifying installed library =====\n")

installed <- vapply(
  names(records),
  function(package) nzchar(system.file(package = package)),
  logical(1)
)

missing <- names(records)[!installed]

if (length(missing)) {
  stop(
    sprintf(
      "%d of %d lockfile packages are not installed: %s",
      length(missing),
      length(records),
      paste(missing, collapse = ", ")
    )
  )
}

# Lockfile versions are occasionally recorded with a leading "v" (a git tag
# rather than a package version), which never matches DESCRIPTION.
pinned <- function(package) sub("^v", "", records[[package]]$Version)

drifted <- Filter(
  function(package) {
    !identical(as.character(packageVersion(package)), pinned(package))
  },
  names(records)
)

if (length(drifted)) {
  cat(sprintf("%d package(s) differ from the pinned version:\n", length(drifted)))
  for (package in drifted) {
    cat(sprintf(
      "  %-32s lockfile %-14s installed %s\n",
      package,
      pinned(package),
      as.character(packageVersion(package))
    ))
  }
}

cat(sprintf(
  "\nAll %d lockfile packages are installed in %s\n",
  length(records),
  .libPaths()[1]
))
