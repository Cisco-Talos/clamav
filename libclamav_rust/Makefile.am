#
# Rust common libs for ClamAV apps
#

rdiff_SOURCES = \
    rdiff/Cargo.toml \
    rdiff/rdiff.rs

EXTRA_DIST = $(rdiff_SOURCES)

$(top_builddir)/common_rust/rdiff/$(RUST_TARGET_SUBDIR)/librdiff.a: $(rdiff_SOURCES)
	cd $(top_srcdir)/common_rust/rdiff && \
	mkdir -p $(top_builddir)/common_rust/rdiff && \
	CARGO_TARGET_DIR=$(top_builddir)/common_rust/rdiff cargo build --target-dir $(abs_top_builddir)/common_rust/rdiff $(CARGO_RELEASE_ARGS)

rdiff_LIB=$(top_builddir)/common_rust/rdiff/$(RUST_TARGET_SUBDIR)/librdiff.a

all: $(rdiff_LIB)
