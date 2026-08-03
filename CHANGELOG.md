# Changelog

## [1.2.0] - 2025-08-01
### Added
- UDP scan mode (`--udp` flag)
- CIDR range support for multi-host scanning
- JSON and HTML report output formats

### Fixed
- Timeout handling on filtered ports improved
- Banner grabbing stability on slow hosts

## [1.1.0] - 2025-06-15
### Added
- Service fingerprinting for 18 common ports
- Banner grabbing with configurable timeout
- `--threads` flag for concurrency control

### Changed
- Improved colorized output with severity levels

## [1.0.0] - 2025-05-01
### Initial Release
- Multithreaded TCP port scanner
- JSON report output
- Top 1024 port default scan
