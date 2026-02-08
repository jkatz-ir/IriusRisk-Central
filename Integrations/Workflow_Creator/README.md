# IriusRisk Workflow Creator

## Purpose

The Workflow Creator is a Python-based tool designed to create and manage workflow states in IriusRisk. It allows you to define custom workflow states for your IriusRisk projects, including configuration for threat model locking, report watermarks, and visibility settings.

This tool reads workflow configurations from a JSON input file (`inputs.json`) and automatically creates or updates the workflows in your IriusRisk instance via the IriusRisk API v2.

### Key Features

- **Automated Workflow Creation**: Define workflow states in JSON and deploy them automatically
- **Flexible Configuration**: Support for multiple workflow states with customizable properties
- **Report Management**: Configure report watermarks and visibility for each workflow state
- **Threat Model Control**: Lock or unlock threat models based on workflow state
- **API Integration**: Seamless integration with IriusRisk API v2
- **Validation**: Built-in validation for workflow state configurations

## Installation

### Prerequisites

- Python 3.7 or higher
- An active IriusRisk instance with API access
- IriusRisk API token with workflow management permissions

### Step 1: Clone or Navigate to Directory

```bash
cd /path/to/Workflow_Creator
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate     # On Windows
```

### Step 3: Install Requirements

```bash
pip install -r requirements.txt
```

The following packages will be installed:
- `requests` - HTTP library for API calls
- `python-dotenv` - Environment variable management
- `certifi`, `charset-normalizer`, `idna`, `urllib3` - Supporting dependencies

### Step 4: Configure Environment Variables

Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` and add your IriusRisk credentials:

```
IRIUSRISK_URL=https://your-instance.iriusrisk.com
API_TOKEN=your-api-token-here
```

**Note**: Never commit your `.env` file to version control as it contains sensitive credentials.

## Usage

### Basic Usage

Run the script to create workflows from your `inputs.json` file:

```bash
python create_workflows.py
```

This will:
1. Load workflow configurations from `inputs.json`
2. Validate the workflow state definitions
3. Connect to your IriusRisk instance
4. Create or update the workflows via the API
5. Display success/failure messages for each operation

### Command Line Options

```bash
# Use default inputs.json file
python create_workflows.py

# Use a custom input file
python create_workflows.py --file my-workflows.json

# Display help information
python create_workflows.py --help
```

### Input File Format

The `inputs.json` file defines your workflow configurations. Here's the structure:

```json
{
  "workflows": [
    {
      "name": "Default Project Workflow",
      "description": "Standard workflow for project lifecycle management",
      "states": [
        {
          "referenceId": "initiation",
          "name": "Initiation",
          "description": "Project is being initiated",
          "lockThreatModel": false,
          "projectRoleReplacements": [],
          "reports": {
            "residualRisk": {
              "watermark": "INITIATION",
              "visible": true
            },
            "technicalThreatReport": {
              "watermark": "INITIATION",
              "visible": true
            },
            "technicalCountermeasureReport": {
              "watermark": "INITIATION",
              "visible": true
            },
            "complianceReport": {
              "watermark": "INITIATION",
              "visible": true
            }
          }
        },
        {more workflows...
        }
      ]
    }
  ]
}
```

### Workflow State Properties

| Property | Type | Description |
|----------|------|-------------|
| `referenceId` | string | Unique identifier for the workflow state |
| `name` | string | Display name of the workflow state |
| `description` | string | Brief description of the workflow state |
| `lockThreatModel` | boolean | Whether to prevent editing the threat model in this state |
| `projectRoleReplacements` | array | Role replacement configurations (if any) |
| `reports` | object | Configuration for report watermarks and visibility |

### Default Workflow States

The included `inputs.json` contains the following workflow states:

1. **Initiation** - Project is being initiated
2. **Documentation** - Project documentation is being created
3. **Threat Identification** - Threats are being identified
4. **Mitigation Assessment** - Mitigation strategies are being assessed
5. **Final Review** - Project is undergoing final review
6. **Archived** - Project has been archived (threat model locked)
7. **On Hold** - Project temporarily paused

### Expected Output

When successfully executed, you'll see output similar to:

```
✓ Loaded workflow configuration from inputs.json
✓ Retrieved current workflow
✓ Workflow update request accepted (async)
  Operation ID: abc123...
✓ Workflow created/updated successfully!
```

### Troubleshooting

**Error: Missing required environment variables**
- Ensure your `.env` file exists and contains `IRIUSRISK_URL` and `API_TOKEN`

**Error: Failed to get workflow**
- Verify your IriusRisk URL is correct and accessible
- Check that your API token has the necessary permissions

**Error: Invalid JSON in inputs.json**
- Validate your JSON syntax using a JSON validator
- Ensure all required fields are present in each workflow state

**Error: Missing required field**
- Review the workflow state properties table above
- Ensure each state includes all required fields

### API Version

This tool uses IriusRisk API v2. Ensure your IriusRisk instance supports API v2 endpoints.

## Support

For issues or questions:
- Review the IriusRisk API documentation
- Check the example configurations in the repository
- Verify your API token has appropriate permissions
