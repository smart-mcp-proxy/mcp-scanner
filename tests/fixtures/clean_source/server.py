"""A clean MCP server for testing."""
import json
import sys


def handle_request(request):
    """Handle an MCP request."""
    method = request.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "add",
                    "description": "Add two numbers together",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                        "required": ["a", "b"],
                    },
                }
            ]
        }
    elif method == "tools/call":
        params = request.get("params", {})
        if params.get("name") == "add":
            args = params.get("arguments", {})
            result = args.get("a", 0) + args.get("b", 0)
            return {"content": [{"type": "text", "text": str(result)}]}
    return {"error": {"code": -32601, "message": "Method not found"}}


def main():
    for line in sys.stdin:
        request = json.loads(line)
        response = handle_request(request)
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
