# WebReconTool

A high-performance, concurrent web reconnaissance and vulnerability assessment engine built in Go. 

Designed for enterprise-grade security research, this tool replaces traditional Python scripts with a compiled, modular architecture optimized for speed and extensive coverage on Linux deployments.

## Features

* **Concurrent Execution Engine:** Built entirely in Go, leveraging goroutines for rapid, simultaneous task execution.
* **18 Security Modules:** Features a highly modular architecture including:
  * Subdomain enumeration
  * Port scanning
  * Directory fuzzing
  * Vulnerability detection
* **Live Discord Alerting:** Integrates directly with Discord webhooks to push real-time alerts for critical findings during live engagements.
* **Optimized Reporting:** Generates clean, structured JSON reports for each target.

## Installation

Ensure you have [Go](https://go.dev/) installed on your system.

1. Clone the repository:
   `git clone https://github.com/nishadhulhasan/webrecon.git`
2. Navigate to the directory:
   `cd webrecon`
3. Download dependencies:
   `go mod tidy`
4. Build the executable:
   `go build -o webrecon main.go`

## Configuration
Before running the tool, create a `.env` or `config.json` file in the root directory to configure your Discord webhook URL for live alerting. *(Note: Ensure this file remains in your `.gitignore` to prevent exposing your webhook).*

## Usage
Run the compiled binary against your target:
`./webrecon -target example.com`
