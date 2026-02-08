#!/usr/bin/env python3
"""
IriusRisk Workflow Builder

This script creates and updates workflows in IriusRisk.
Configuration is loaded from environment variables via .env file.

Author: IriusRisk Integration Team
"""

import os
import sys
import json
import requests
from dotenv import load_dotenv
from typing import Dict, List, Optional, Any, cast
from pathlib import Path

# Load environment variables
load_dotenv()

# Configuration (support multiple env var names for flexibility)
IRIUSRISK_URL = os.getenv("IRIUSRISK_URL") or os.getenv("IRIUSRISK_DOMAIN") or os.getenv("IRIUSRISK_HOST")
API_TOKEN = os.getenv("API_TOKEN") or os.getenv("IRIUSRISK_API_TOKEN")

if not IRIUSRISK_URL or not API_TOKEN:
    print("ERROR: Missing required environment variables.")
    print("Please ensure IRIUSRISK_URL (or IRIUSRISK_DOMAIN) and API_TOKEN (or IRIUSRISK_API_TOKEN) are set in your .env file.")
    sys.exit(1)

# Remove trailing slash from URL if present
IRIUSRISK_URL = cast(str, IRIUSRISK_URL).rstrip('/')
API_TOKEN = cast(str, API_TOKEN)

# API Endpoints
BASE_API_URL = f"{IRIUSRISK_URL}/api/v2"
WORKFLOW_URL = f"{BASE_API_URL}/workflow"


class IriusRiskWorkflowBuilder:
    """Main class for building and managing workflows in IriusRisk."""
    
    def __init__(self, api_token: str, base_url: str):
        """
        Initialize the builder.
        
        Args:
            api_token: IriusRisk API token
            base_url: Base URL for the API
        """
        self.api_token = api_token
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "api-token": self.api_token,
            "Content-Type": "application/json",
            "Accept": "application/hal+json"
        })
    
    def get_workflow(self) -> Optional[Dict[str, Any]]:
        """
        Get the current workflow configuration.
        
        Returns:
            Current workflow data or None if failed
        """
        try:
            response = self.session.get(f"{self.base_url}/workflow")
            response.raise_for_status()
            result = response.json()
            print(f"✓ Retrieved current workflow")
            
            # Handle paginated response
            if '_embedded' in result and 'items' in result['_embedded']:
                return {'states': result['_embedded']['items']}
            return result
        except Exception as e:
            print(f"✗ Failed to get workflow: {e}")
            return None
    
    def update_workflow(self, states: List[Dict[str, Any]], 
                       delete_replacements: Optional[List[Dict[str, Any]]] = None,
                       async_mode: bool = True) -> Optional[Dict[str, Any]]:
        """
        Update the workflow with new states.
        
        Args:
            states: List of workflow state configurations
            delete_replacements: List of state replacements for deleted states
            async_mode: Whether to use async processing (default: True)
            
        Returns:
            Response data if successful, None otherwise
        """
        # Clean states to match API response format
        cleaned_states = []
        for state in states:
            cleaned_state = {
                "referenceId": state.get("referenceId"),
                "name": state.get("name"),
                "description": state.get("description"),
                "lockThreatModel": state.get("lockThreatModel"),
                "reports": state.get("reports"),
                "projectRoleReplacements": state.get("projectRoleReplacements", [])
            }
            # CRITICAL: Preserve the 'id' field for existing states to avoid deletion
            if "id" in state:
                cleaned_state["id"] = state["id"]
            cleaned_states.append(cleaned_state)
        
        payload = {
            "workflow": cleaned_states,
            "deleteReplacements": delete_replacements or []
        }
        
        try:
            headers = {
                "X-Irius-Async": "true" if async_mode else "false"
            }
            
            response = self.session.put(
                f"{self.base_url}/workflow",
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            result = response.json()
            
            if response.status_code == 202:
                print(f"✓ Workflow update request accepted (async)")
                if 'operationId' in result:
                    print(f"  Operation ID: {result['operationId']}")
            else:
                print(f"✓ Workflow updated successfully")
            
            return result
        except requests.exceptions.HTTPError as e:
            print(f"✗ Failed to update workflow: {e}")
            if e.response.text:
                print(f"  Error details: {e.response.text}")
            return None
        except Exception as e:
            print(f"✗ Unexpected error updating workflow: {e}")
            return None


def load_inputs_file(file_path: str = "inputs.json") -> Optional[Dict[str, Any]]:
    """
    Load the inputs JSON file.
    
    Args:
        file_path: Path to the inputs JSON file
        
    Returns:
        Parsed JSON data or None if failed
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        print(f"✓ Loaded workflow configuration from {file_path}")
        return data
    except FileNotFoundError:
        print(f"✗ File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON in {file_path}: {e}")
        return None
    except Exception as e:
        print(f"✗ Error loading {file_path}: {e}")
        return None


def validate_state_config(state: Dict[str, Any]) -> bool:
    """
    Validate a workflow state configuration.
    
    Args:
        state: Workflow state configuration to validate
        
    Returns:
        True if valid, False otherwise
    """
    required_fields = ['referenceId', 'name', 'description', 'lockThreatModel', 
                      'projectRoleReplacements', 'reports']
    
    for field in required_fields:
        if field not in state:
            print(f"  ⚠️  Missing required field '{field}' in state '{state.get('name', 'Unknown')}'")
            return False
    
    # Validate reports structure - must contain all 4 report types
    if state.get('reports'):
        reports = state['reports']
        required_report_types = ['residualRisk', 'technicalThreatReport', 
                                'technicalCountermeasureReport', 'complianceReport']
        
        for report_type in required_report_types:
            if report_type not in reports:
                print(f"  ⚠️  Missing '{report_type}' in reports for state '{state.get('name')}'")
                return False
            
            # Each report type must have visible property
            if not isinstance(reports[report_type], dict) or 'visible' not in reports[report_type]:
                print(f"  ⚠️  Missing 'visible' property in {report_type} for state '{state.get('name')}'")
                return False
    
    return True


def build_workflow_from_inputs(builder: 'IriusRiskWorkflowBuilder', 
                               inputs_data: Dict[str, Any]) -> bool:
    """
    Build workflows from input configuration.
    
    Args:
        builder: IriusRiskWorkflowBuilder instance
        inputs_data: Parsed inputs JSON data
        
    Returns:
        True if successful, False otherwise
    """
    workflows = inputs_data.get('workflows', [])
    
    if not workflows:
        print("⚠️  No workflows found in inputs file")
        return False
    
    print(f"\nProcessing {len(workflows)} workflow(s)")
    print("=" * 80)
    
    # For now, we support updating a single global workflow
    # IriusRisk has one system-wide workflow that applies to all projects
    if len(workflows) > 1:
        print("⚠️  Multiple workflows detected. IriusRisk uses a single system workflow.")
        print("   Only the first workflow will be applied.")
    
    workflow_config = workflows[0]
    workflow_name = workflow_config.get('name', 'Workflow')
    workflow_description = workflow_config.get('description', '')
    states = workflow_config.get('states', [])
    
    print(f"\n📋 Workflow: {workflow_name}")
    if workflow_description:
        print(f"   Description: {workflow_description}")
    print(f"   States to create/update: {len(states)}")
    print("-" * 80)
    
    # Validate all states first
    valid_states = []
    for state in states:
        if validate_state_config(state):
            valid_states.append(state)
        else:
            print(f"  ✗ Invalid state configuration: {state.get('name', 'Unknown')}")
    
    if not valid_states:
        print("✗ No valid states to apply")
        return False
    
    # Get current workflow to determine what states exist
    current_workflow = builder.get_workflow()
    if not current_workflow:
        print("✗ Could not retrieve current workflow")
        return False
    
    current_states = current_workflow.get('states', [])
    
    # Build list of state references from inputs
    input_state_refs = {state.get('referenceId'): state for state in valid_states}
    
    # Non-destructive update: merge existing states with new ones from inputs
    final_states = list(current_states)  # Start with all current states
    
    # Update or add states from inputs file
    for new_state in valid_states:
        new_ref = new_state.get('referenceId')
        # Find if this state already exists
        existing_idx = None
        for i, state in enumerate(final_states):
            if state.get('referenceId') == new_ref:
                existing_idx = i
                break
        
        if existing_idx is not None:
            # Update existing state - preserve 'id' and other API-returned fields
            existing_state = final_states[existing_idx]
            # Keep the id from the existing state
            state_id = existing_state.get('id')
            final_states[existing_idx].update(new_state)
            if state_id:
                final_states[existing_idx]['id'] = state_id
        else:
            # Add new state
            final_states.append(new_state)
    
    # No delete replacements needed - we're keeping all existing states
    delete_replacements = []
    
    # Update workflow with merged states
    print(f"\n📝 Updating workflow...")
    print(f"  - Updating {len(valid_states)} state(s) from inputs")
    print(f"  - Total states in workflow: {len(final_states)}")
    print("-" * 80)
    
    result = builder.update_workflow(
        states=final_states,
        delete_replacements=delete_replacements,
        async_mode=True
    )
    
    if result:
        print("\n" + "=" * 80)
        print("✓ Workflow updated successfully!")
        print("=" * 80)
        return True
    else:
        print("\n" + "=" * 80)
        print("✗ Failed to update workflow")
        print("=" * 80)
        return False


def create_from_inputs_file(inputs_file: str = "inputs.json"):
    """
    Create/update workflows from an inputs JSON file.
    
    Args:
        inputs_file: Path to the inputs JSON file
    """
    print("=" * 80)
    print("IriusRisk Workflow Builder")
    print("=" * 80)
    print()
    
    # Load the inputs file
    inputs_data = load_inputs_file(inputs_file)
    if not inputs_data:
        print("\n❌ Failed to load inputs file. Exiting.")
        return False
    
    # Initialize the builder
    builder = IriusRiskWorkflowBuilder(API_TOKEN, BASE_API_URL)
    
    # Get current workflow
    print("\nRetrieving current workflow...")
    current_workflow = builder.get_workflow()
    if current_workflow:
        current_states = current_workflow.get('states', [])
        print(f"  Current states: {len(current_states)}")
    
    # Build workflow from inputs
    success = build_workflow_from_inputs(builder, inputs_data)
    
    return success


def example_usage():
    """Example usage demonstrating how to create workflows."""
    
    print("=" * 80)
    print("IriusRisk Workflow Builder - Example")
    print("=" * 80)
    print()
    
    # Initialize the builder
    builder = IriusRiskWorkflowBuilder(API_TOKEN, BASE_API_URL)
    
    # Define a workflow with states
    print("Creating a sample workflow...")
    print("-" * 80)
    
    states = [
        {
            "referenceId": "not-started",
            "name": "Not Started",
            "description": "Project has not been started",
            "lockThreatModel": False,
            "projectRoleReplacements": [],
            "reports": {
                "watermark": "NOT APPLICABLE",
                "showThreatsPerStatus": True,
                "showCountermeasuresPerStatus": True
            }
        },
        {
            "referenceId": "in-progress",
            "name": "In Progress",
            "description": "Project is being analyzed",
            "lockThreatModel": False,
            "projectRoleReplacements": [],
            "reports": {
                "watermark": "DRAFT",
                "showThreatsPerStatus": True,
                "showCountermeasuresPerStatus": True
            }
        },
        {
            "referenceId": "completed",
            "name": "Completed",
            "description": "Project analysis is complete",
            "lockThreatModel": True,
            "projectRoleReplacements": [],
            "reports": {
                "watermark": "FINAL",
                "showThreatsPerStatus": True,
                "showCountermeasuresPerStatus": True
            }
        }
    ]
    
    print(f"✓ Defined {len(states)} workflow states")
    for state in states:
        print(f"  - {state['name']} (ref: {state['referenceId']})")
    
    # Update workflow
    print("\n📝 Updating workflow...")
    result = builder.update_workflow(states=states, async_mode=True)
    
    if result:
        print("✓ Workflow update successful!")
    else:
        print("✗ Workflow update failed")
    
    print()


def main():
    """Main entry point."""
    try:
        # Check if user wants to use inputs.json or run examples
        if len(sys.argv) > 1:
            if sys.argv[1] == '--example':
                print("Running example usage...\n")
                example_usage()
            elif sys.argv[1] == '--help':
                print("IriusRisk Workflow Builder")
                print("\nUsage:")
                print("  python create_workflows.py              # Create workflows from inputs.json")
                print("  python create_workflows.py --example    # Run example demonstrations")
                print("  python create_workflows.py --file FILE  # Use custom input file")
                print("  python create_workflows.py --help       # Show this help message")
            elif sys.argv[1] == '--file' and len(sys.argv) > 2:
                create_from_inputs_file(sys.argv[2])
            else:
                print(f"Unknown argument: {sys.argv[1]}")
                print("Use --help for usage information")
        else:
            # Default: use inputs.json
            create_from_inputs_file()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
