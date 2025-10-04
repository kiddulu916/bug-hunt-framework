#!/usr/bin/env python
"""
Intelligent Testing Suite Runner

Easy-to-use script for running the Phase 4 Intelligent Testing Suite
with various configuration options and intelligence levels.
"""

import os
import sys
import subprocess
import argparse
import json
from pathlib import Path


def setup_environment():
    """Setup environment for intelligent testing"""
    # Add project root and backend to Python path
    project_root = Path(__file__).parent.parent
    backend_path = project_root / 'backend'
    sys.path.insert(0, str(project_root))
    sys.path.insert(0, str(backend_path))

    # Set Python path in environment for subprocesses
    current_pythonpath = os.environ.get('PYTHONPATH', '')
    new_pythonpath = f"{project_root}:{backend_path}:{current_pythonpath}" if current_pythonpath else f"{project_root}:{backend_path}"
    os.environ['PYTHONPATH'] = new_pythonpath

    # Set Django settings
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')

    # Set intelligence configuration
    os.environ.setdefault('INTELLIGENCE_LEVEL', 'phase4')

    print("✅ Environment configured for intelligent testing")


def run_neural_optimization(args):
    """Run neural optimization tests"""
    print("🧠 Running Neural Network-Based Optimization Tests...")

    cmd = [
        'pytest',
        'backend/tests/intelligence/test_neural_optimization.py',
        '-v',
        '--tb=short'
    ]

    if args.quick:
        cmd.extend(['-k', 'not test_continual_learning'])

    if args.specific:
        cmd.extend(['-k', args.specific])

    result = subprocess.run(cmd, env=os.environ)
    return result.returncode == 0


def run_distributed_intelligence(args):
    """Run distributed intelligence tests"""
    print("🤖 Running Distributed Intelligence Coordination Tests...")

    cmd = [
        'pytest',
        'backend/tests/intelligence/test_distributed_intelligence.py',
        '-v',
        '--tb=short'
    ]

    if args.quick:
        cmd.extend(['-k', 'not test_emergent_behavior'])

    if args.specific:
        cmd.extend(['-k', args.specific])

    result = subprocess.run(cmd, env=os.environ)
    return result.returncode == 0


def run_self_modifying_architecture(args):
    """Run self-modifying architecture tests"""
    print("🔧 Running Self-Modifying Architecture Tests...")

    cmd = [
        'pytest',
        'backend/tests/intelligence/test_self_modifying_architecture.py',
        '-v',
        '--tb=short'
    ]

    if args.quick:
        cmd.extend(['-k', 'not test_continuous_architecture_learning'])

    if args.specific:
        cmd.extend(['-k', args.specific])

    result = subprocess.run(cmd, env=os.environ)
    return result.returncode == 0


def run_all_intelligence_tests(args):
    """Run all intelligence tests"""
    print("🚀 Running Complete Phase 4 Intelligent Testing Suite...")

    cmd = [
        'pytest',
        'backend/tests/intelligence/',
        '-v',
        '--tb=short'
    ]

    if args.quick:
        cmd.extend(['-k', 'not (continual_learning or emergent_behavior or continuous_architecture_learning)'])

    if args.parallel:
        cmd.extend(['-n', str(args.parallel)])

    if args.markers:
        cmd.extend(['-m', args.markers])

    result = subprocess.run(cmd, env=os.environ)
    return result.returncode == 0


def run_specific_algorithm(args):
    """Run specific algorithm tests"""
    algorithm_map = {
        'drl': 'deep_reinforcement_learning',
        'transformer': 'transformer_based',
        'gnn': 'graph_neural_network',
        'swarm': 'swarm_coordination',
        'consensus': 'consensus_based',
        'genetic': 'genetic_algorithm',
        'meta_learning': 'meta_learning',
        'nas': 'neural_architecture_search',
        'quantum': 'quantum_inspired'
    }

    algorithm_key = algorithm_map.get(args.algorithm)
    if not algorithm_key:
        print(f"❌ Unknown algorithm: {args.algorithm}")
        print(f"Available algorithms: {', '.join(algorithm_map.keys())}")
        return False

    print(f"🎯 Running {args.algorithm.upper()} Algorithm Tests...")

    cmd = [
        'pytest',
        'backend/tests/intelligence/',
        '-v',
        '--tb=short',
        '-k',
        algorithm_key
    ]

    result = subprocess.run(cmd, env=os.environ)
    return result.returncode == 0


def run_demo_workflow(args):
    """Run demonstration workflow"""
    print("🎬 Running Intelligent Testing Demo Workflow...")

    # Create demo script content
    demo_script = '''
import sys
import os
sys.path.append(os.path.abspath('.'))

from backend.tests.intelligence.test_neural_optimization import NeuralTestOptimizer
from backend.tests.intelligence.test_distributed_intelligence import DistributedIntelligenceSystem
from backend.tests.intelligence.test_self_modifying_architecture import SelfModifyingTestSystem

def demo_workflow():
    print("=== INTELLIGENT TESTING DEMO ===\\n")

    # 1. Neural Optimization Demo
    print("1. 🧠 Neural Optimization Demo")
    neural_optimizer = NeuralTestOptimizer()
    drl_agent = neural_optimizer.create_drl_agent()
    print("   ✅ DRL Agent created")

    transformer = neural_optimizer.create_transformer_model()
    print("   ✅ Transformer model created")

    gnn = neural_optimizer.create_gnn_model()
    print("   ✅ Graph Neural Network created")
    print()

    # 2. Distributed Intelligence Demo
    print("2. 🤖 Distributed Intelligence Demo")
    distributed_system = DistributedIntelligenceSystem()
    swarm = distributed_system.create_agent_swarm(5)
    print("   ✅ Agent swarm created (5 agents)")

    hierarchy = distributed_system.create_agent_hierarchy()
    print("   ✅ Hierarchical agent system created")

    consensus = distributed_system.create_consensus_network(7)
    print("   ✅ Consensus network created (7 agents)")
    print()

    # 3. Self-Modifying Architecture Demo
    print("3. 🔧 Self-Modifying Architecture Demo")
    self_modifying = SelfModifyingTestSystem()
    population = self_modifying.create_initial_population(10)
    print("   ✅ Evolutionary population created (10 individuals)")

    code_generator = self_modifying.create_dynamic_code_generator()
    print("   ✅ Dynamic code generator created")

    healing_system = self_modifying.create_self_healing_system()
    print("   ✅ Self-healing system created")
    print()

    print("🎉 Demo completed successfully!")
    print("All intelligent systems are operational and ready for use.")

    return True

if __name__ == "__main__":
    demo_workflow()
'''

    # Write and execute demo script
    demo_file = Path("temp_demo.py")
    demo_file.write_text(demo_script)

    try:
        result = subprocess.run([sys.executable, str(demo_file)], env=os.environ)
        success = result.returncode == 0
    finally:
        demo_file.unlink()  # Clean up

    return success


def setup_intelligence_config(args):
    """Setup custom intelligence configuration"""
    config = {
        'neural_optimization': {
            'drl_episodes': args.drl_episodes or 50,
            'transformer_layers': args.transformer_layers or 4,
            'gnn_hidden_dims': args.gnn_dims or 128,
            'learning_rate': args.learning_rate or 0.001
        },
        'distributed_intelligence': {
            'swarm_size': args.swarm_size or 5,
            'consensus_threshold': args.consensus_threshold or 0.7,
            'hierarchy_levels': args.hierarchy_levels or 3
        },
        'self_modifying': {
            'population_size': args.population_size or 10,
            'evolution_generations': args.generations or 15,
            'mutation_rate': args.mutation_rate or 0.1
        }
    }

    # Set environment variables
    os.environ['INTELLIGENCE_CONFIG'] = json.dumps(config)
    os.environ['DRL_EPISODES'] = str(config['neural_optimization']['drl_episodes'])
    os.environ['SWARM_SIZE'] = str(config['distributed_intelligence']['swarm_size'])
    os.environ['POPULATION_SIZE'] = str(config['self_modifying']['population_size'])

    if args.quick:
        # Reduce parameters for quick testing
        os.environ['QUICK_MODE'] = 'true'
        os.environ['DRL_EPISODES'] = '10'
        os.environ['SWARM_SIZE'] = '3'
        os.environ['POPULATION_SIZE'] = '5'

    print(f"📋 Intelligence configuration applied:")
    print(f"   Neural: {config['neural_optimization']}")
    print(f"   Distributed: {config['distributed_intelligence']}")
    print(f"   Self-Modifying: {config['self_modifying']}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Intelligent Testing Suite Runner')

    # Main action
    parser.add_argument('action', choices=[
        'neural', 'distributed', 'self-modifying', 'all', 'algorithm', 'demo'
    ], help='Which intelligence tests to run')

    # Algorithm selection
    parser.add_argument('--algorithm', choices=[
        'drl', 'transformer', 'gnn', 'swarm', 'consensus', 'genetic',
        'meta_learning', 'nas', 'quantum'
    ], help='Specific algorithm to test')

    # Test options
    parser.add_argument('--quick', action='store_true',
                        help='Run quick tests (reduced training/generations)')
    parser.add_argument('--specific', type=str,
                        help='Run specific test methods (pytest -k)')
    parser.add_argument('--parallel', type=int,
                        help='Number of parallel test workers')
    parser.add_argument('--markers', type=str,
                        help='Pytest markers to run (e.g., "phase4 and not slow")')

    # Configuration options
    parser.add_argument('--drl-episodes', type=int, default=50,
                        help='Number of DRL training episodes')
    parser.add_argument('--transformer-layers', type=int, default=4,
                        help='Number of transformer layers')
    parser.add_argument('--gnn-dims', type=int, default=128,
                        help='GNN hidden dimensions')
    parser.add_argument('--learning-rate', type=float, default=0.001,
                        help='Neural network learning rate')
    parser.add_argument('--swarm-size', type=int, default=5,
                        help='Swarm intelligence agent count')
    parser.add_argument('--consensus-threshold', type=float, default=0.7,
                        help='Consensus agreement threshold')
    parser.add_argument('--hierarchy-levels', type=int, default=3,
                        help='Hierarchical agent system levels')
    parser.add_argument('--population-size', type=int, default=10,
                        help='Genetic algorithm population size')
    parser.add_argument('--generations', type=int, default=15,
                        help='Genetic algorithm generations')
    parser.add_argument('--mutation-rate', type=float, default=0.1,
                        help='Genetic algorithm mutation rate')

    args = parser.parse_args()

    # Setup environment
    setup_environment()
    setup_intelligence_config(args)

    # Route to appropriate function
    success = False

    if args.action == 'neural':
        success = run_neural_optimization(args)
    elif args.action == 'distributed':
        success = run_distributed_intelligence(args)
    elif args.action == 'self-modifying':
        success = run_self_modifying_architecture(args)
    elif args.action == 'all':
        success = run_all_intelligence_tests(args)
    elif args.action == 'algorithm':
        if not args.algorithm:
            print("❌ --algorithm required when using 'algorithm' action")
            return 1
        success = run_specific_algorithm(args)
    elif args.action == 'demo':
        success = run_demo_workflow(args)

    if success:
        print("✅ Intelligence tests completed successfully!")
        return 0
    else:
        print("❌ Intelligence tests failed!")
        return 1


if __name__ == '__main__':
    sys.exit(main())