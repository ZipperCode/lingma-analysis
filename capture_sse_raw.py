"""Capture raw SSE stream from Lingma chat to analyze tool call events."""
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lingma_remote_api import LingmaRemoteAPI


def capture_raw_sse(question: str, output_file: str, model: str = '', task_id: str = 'agent_chat_generation'):
    """Send a chat request and save the complete raw SSE response."""
    api = LingmaRemoteAPI()
    api._read_credentials()

    path = api.CHAT_PATH
    query = '?FetchKeys=llm_model_result&AgentId=agent_common'
    full_path = path + query

    body = api._build_chat_body(question, task_id=task_id, model=model)
    headers = api._make_headers(path, body)

    cmd = ['curl', '-s', '--compressed', '--max-time', '120', '-N']
    for k, v in headers.items():
        cmd.extend(['-H', f'{k}: {v}'])
    cmd.extend(['-d', body, f'{api.BASE_URL}{full_path}'])

    print(f"Sending: {question}")
    print(f"Model: {model or 'auto'}")
    print(f"Task: {task_id}")
    print(f"Saving raw SSE to: {output_file}")
    print()

    import subprocess
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=130)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(result.stdout)

    print(f"Raw SSE saved ({len(result.stdout)} bytes)")
    if result.stderr:
        print(f"Stderr: {result.stderr[:500]}")

    return result.stdout


def analyze_sse(raw: str):
    """Parse and categorize SSE events."""
    events = []
    for line in raw.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('data:'):
            data_str = line[5:]
            if data_str == '[DONE]':
                events.append({'type': 'done'})
                continue
            try:
                outer = json.loads(data_str)
                events.append(outer)
            except json.JSONDecodeError:
                events.append({'type': 'raw', 'data': data_str[:200]})
        elif line.startswith('event:'):
            events.append({'sse_event': line[6:].strip()})
        elif line.startswith('id:'):
            events.append({'sse_id': line[3:].strip()})
        else:
            events.append({'type': 'unknown', 'line': line[:200]})

    # Categorize
    tool_events = []
    content_events = []
    other_events = []

    for evt in events:
        if 'sse_event' in evt or 'sse_id' in evt:
            other_events.append(evt)
            continue

        body = evt.get('body', '')
        if not body or body == '[DONE]':
            if evt.get('type') == 'done':
                other_events.append(evt)
            continue

        try:
            inner = json.loads(body) if isinstance(body, str) else body
        except json.JSONDecodeError:
            other_events.append(evt)
            continue

        # Check for tool-related keys
        is_tool = False
        for choice in inner.get('choices', []):
            delta = choice.get('delta', {})
            if 'tool_calls' in delta:
                is_tool = True
            if delta.get('tool_call_id'):
                is_tool = True

        # Check other tool indicators
        for key in inner:
            if 'tool' in key.lower():
                is_tool = True

        if is_tool:
            tool_events.append(evt)
        elif any('content' in str(choice.get('delta', {})) for choice in inner.get('choices', [])):
            content_events.append(evt)
        else:
            other_events.append(evt)

    return {
        'total': len(events),
        'tool_events': tool_events,
        'content_events': len(content_events),
        'other_events': other_events[:20],
    }


if __name__ == '__main__':
    prompts = [
        ("Reply with just the word: Success", "test_basic.txt"),
        ("List all Python files in the current directory using a tool", "test_tool_trigger.txt"),
    ]

    if len(sys.argv) > 1:
        prompt = sys.argv[1]
        outfile = sys.argv[2] if len(sys.argv) > 2 else "sse_output.txt"
        raw = capture_raw_sse(prompt, outfile)
        analysis = analyze_sse(raw)
        print(f"\n=== Analysis ===")
        print(f"Total events: {analysis['total']}")
        print(f"Tool events: {len(analysis['tool_events'])}")
        print(f"Content events: {analysis['content_events']}")
        if analysis['tool_events']:
            print(f"\n=== Tool Events ===")
            for evt in analysis['tool_events'][:10]:
                print(json.dumps(evt, indent=2, ensure_ascii=False)[:500])
        if analysis['other_events']:
            print(f"\n=== Other Events (first 5) ===")
            for evt in analysis['other_events'][:5]:
                print(json.dumps(evt, indent=2, ensure_ascii=False)[:300])
    else:
        # Default: just test basic chat
        raw = capture_raw_sse("What tools do you have available? Please list them.", "sse_tool_probe.txt")
        analysis = analyze_sse(raw)
        print(f"\n=== Analysis ===")
        print(f"Total events: {analysis['total']}")
        print(f"Tool events: {len(analysis['tool_events'])}")
        print(f"Content events: {analysis['content_events']}")
        if analysis['tool_events']:
            print(f"\n=== Tool Events ===")
            for evt in analysis['tool_events'][:10]:
                print(json.dumps(evt, indent=2, ensure_ascii=False)[:500])
        if analysis['other_events']:
            print(f"\n=== Other Events (first 10) ===")
            for evt in analysis['other_events'][:10]:
                print(json.dumps(evt, indent=2, ensure_ascii=False)[:500])
