#!/bin/bash
# Intelligent Testing Suite Bash Wrapper
# Easy-to-use commands for running intelligent tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment if it exists
if [ -f "$PROJECT_ROOT/.venv/bin/activate" ]; then
    echo -e "${GREEN}Activating virtual environment...${NC}"
    source "$PROJECT_ROOT/.venv/bin/activate"
fi

# Change to project directory
cd "$PROJECT_ROOT"

# Function to show usage
show_usage() {
    echo -e "${CYAN}🧠 Intelligent Testing Suite${NC}"
    echo -e "${CYAN}===============================${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 <command> [options]"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  ${GREEN}demo${NC}           - Run demonstration workflow"
    echo -e "  ${GREEN}neural${NC}         - Run neural optimization tests"
    echo -e "  ${GREEN}distributed${NC}    - Run distributed intelligence tests"
    echo -e "  ${GREEN}self-modify${NC}    - Run self-modifying architecture tests"
    echo -e "  ${GREEN}all${NC}            - Run all intelligence tests"
    echo -e "  ${GREEN}quick${NC}          - Run quick tests (reduced parameters)"
    echo ""
    echo -e "${YELLOW}Algorithm-Specific:${NC}"
    echo -e "  ${GREEN}drl${NC}            - Deep Reinforcement Learning tests"
    echo -e "  ${GREEN}transformer${NC}    - Transformer-based tests"
    echo -e "  ${GREEN}gnn${NC}            - Graph Neural Network tests"
    echo -e "  ${GREEN}swarm${NC}          - Swarm intelligence tests"
    echo -e "  ${GREEN}genetic${NC}        - Genetic algorithm tests"
    echo -e "  ${GREEN}quantum${NC}        - Quantum-inspired optimization tests"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 demo                    # Run demonstration"
    echo "  $0 neural --quick          # Run neural tests quickly"
    echo "  $0 swarm                   # Run swarm intelligence tests"
    echo "  $0 all --parallel 4        # Run all tests with 4 workers"
    echo ""
}

# Function to run demo
run_demo() {
    echo -e "${PURPLE}🎬 Running Intelligent Testing Demo...${NC}"
    python scripts/run_intelligent_tests.py demo
}

# Function to run neural tests
run_neural() {
    echo -e "${BLUE}🧠 Running Neural Optimization Tests...${NC}"
    python scripts/run_intelligent_tests.py neural "$@"
}

# Function to run distributed tests
run_distributed() {
    echo -e "${CYAN}🤖 Running Distributed Intelligence Tests...${NC}"
    python scripts/run_intelligent_tests.py distributed "$@"
}

# Function to run self-modifying tests
run_self_modify() {
    echo -e "${YELLOW}🔧 Running Self-Modifying Architecture Tests...${NC}"
    python scripts/run_intelligent_tests.py self-modifying "$@"
}

# Function to run all tests
run_all() {
    echo -e "${GREEN}🚀 Running All Intelligence Tests...${NC}"
    python scripts/run_intelligent_tests.py all "$@"
}

# Function to run quick tests
run_quick() {
    echo -e "${GREEN}⚡ Running Quick Intelligence Tests...${NC}"
    python scripts/run_intelligent_tests.py all --quick "$@"
}

# Function to run specific algorithm
run_algorithm() {
    local algorithm=$1
    shift
    echo -e "${PURPLE}🎯 Running ${algorithm^^} Algorithm Tests...${NC}"
    python scripts/run_intelligent_tests.py algorithm --algorithm "$algorithm" "$@"
}

# Main logic
case "${1:-}" in
    "demo")
        shift
        run_demo "$@"
        ;;
    "neural")
        shift
        run_neural "$@"
        ;;
    "distributed")
        shift
        run_distributed "$@"
        ;;
    "self-modify")
        shift
        run_self_modify "$@"
        ;;
    "all")
        shift
        run_all "$@"
        ;;
    "quick")
        shift
        run_quick "$@"
        ;;
    "drl")
        shift
        run_algorithm "drl" "$@"
        ;;
    "transformer")
        shift
        run_algorithm "transformer" "$@"
        ;;
    "gnn")
        shift
        run_algorithm "gnn" "$@"
        ;;
    "swarm")
        shift
        run_algorithm "swarm" "$@"
        ;;
    "genetic")
        shift
        run_algorithm "genetic" "$@"
        ;;
    "quantum")
        shift
        run_algorithm "quantum" "$@"
        ;;
    "consensus")
        shift
        run_algorithm "consensus" "$@"
        ;;
    "nas")
        shift
        run_algorithm "nas" "$@"
        ;;
    "meta_learning")
        shift
        run_algorithm "meta_learning" "$@"
        ;;
    "-h"|"--help"|"help"|"")
        show_usage
        ;;
    *)
        echo -e "${RED}❌ Unknown command: $1${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac