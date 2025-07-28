# macLogger

A comprehensive system monitoring and logging tool for macOS written in Rust. macLogger captures and analyzes system events, filesystem activity, and network traffic in real-time, providing structured logging with OpenTelemetry metrics.

## Features

- **System Logging**: Captures system and application logs using `log stream`
- **Filesystem Monitoring**: Tracks file system calls and usage patterns using `fs_usage`
- **Network Traffic Analysis**: Monitors network packets using `tcpdump`
- **Real-time Processing**: Multi-threaded architecture for concurrent event processing
- **Structured Output**: JSON-formatted logs with detailed event information
- **OpenTelemetry Integration**: Built-in metrics collection and histogram analysis
- **Performance Monitoring**: Tracks processing latency with microsecond precision

## Requirements

- macOS (uses macOS-specific system tools)
- Rust 1.70+ 
- Root privileges (for network and filesystem monitoring)

## Usage

macLogger requires root privileges for network and filesystem monitoring. You must specify at least one monitoring option.

### Basic Usage

```bash
# Monitor system logs only
sudo ./target/release/macLogger -s

# Monitor filesystem activity only
sudo ./target/release/macLogger -f

# Monitor network traffic only
sudo ./target/release/macLogger -n

# Monitor all three types simultaneously
sudo ./target/release/macLogger -s -f -n
```

### Command Line Options

- `-s, --system`: Enable system and application log monitoring
- `-f, --filesystem`: Enable filesystem activity monitoring
- `-n, --network`: Enable network traffic monitoring

### Output Format

The tool outputs structured JSON logs with the following event types:

**System Events**: Raw system log entries in JSON format

**Filesystem Events**:
```json
{
  "time": "timestamp",
  "event_type": "operation_type",
  "file_path": "affected_file_path",
  "duration": 0.001234,
  "p_name": "process_name",
  "pid": 12345
}
```

**Network Events**:
```json
{
  "time": "timestamp",
  "len": 1500,
  "req_type_str": "Ip",
  "req_type": {
    "proto": "TCP",
    "payload_len": 1460,
    "source": "192.168.1.100",
    "dest": "8.8.8.8"
  }
}
```

## Architecture

- **Multi-threaded Design**: Separate threads handle each monitoring type
- **Channel-based Communication**: Crossbeam channels for thread-safe message passing
- **Regex-based Parsing**: Efficient pattern matching for log parsing
- **OpenTelemetry Metrics**: Built-in observability with histograms and counters
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM

## Dependencies

- `crossbeam-channel`: Thread-safe message passing
- `opentelemetry`: Metrics collection and export
- `regex`: Pattern matching for log parsing
- `serde`: JSON serialization/deserialization
- `structopt`: Command-line argument parsing
- `nix`: Unix system calls
- `signal-hook`: Signal handling

## Performance

The tool is optimized for low-latency processing with histogram boundaries ranging from 15 microseconds to 10 milliseconds. Processing times are tracked and exported as OpenTelemetry metrics.

## Security

- Requires root privileges for network and filesystem monitoring
- No persistent data storage - all processing is in-memory
- Graceful handling of process termination signals


### Code Formatting

```bash
cargo fmt
```