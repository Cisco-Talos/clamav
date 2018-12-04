# OSS-Fuzz

ClamAV has chosen to integrate with [oss-fuzz](https://github.com/google/oss-fuzz).

What this means is that this repository includes:

- Fuzz targets:
  - A function to which we apply fuzzing.
  - For ClamAV, clamav_scanfile_fuzzer.cc may be compiled with specific macros defined to produce multiple fuzz targets.
  - Additional fuzz targets may be added to fuzz other ClamAV inputs.
  
- Seed corpora:
  - A set of minimal test inputs that generate maximal code coverage.
  - Each ClamAV fuzz target has a seed corpus located under: fuzz/corpus/<target>

- Fuzzing dictionaries:
  - A simple dictionary of tokens used by the input language. This can have a dramatic positive effect on fuzzing efficiency. For example, when fuzzing an XML parser, a dictionary of XML tokens will help.
  - Some ClamAV fuzz targets have a dictionary located under: fuzz/dictionaries/<target>.dict

For more information on how this is set up, see: [ideal OSS-Fuzz integration](https://github.com/google/oss-fuzz/blob/master/docs/ideal_integration.md)
