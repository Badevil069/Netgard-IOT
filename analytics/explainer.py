"""
explainer.py - AI-powered threat explanation module.

Sends device anomaly information to a locally-running Ollama LLM
(``llama3`` model) and returns a plain-English security explanation.

If Ollama is unreachable the module returns a deterministic fallback
explanation built from the device statistics, so the pipeline never
crashes due to a missing LLM service.
"""

import json

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "llama3"
REQUEST_TIMEOUT = 90  # seconds


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_prompt(device_info: dict) -> str:
    """Build a concise prompt for the LLM from device statistics.

    Args:
        device_info: Dictionary containing at least ``ip``, ``status``,
            ``confidence``, ``packets_per_sec``, and ``unique_ports``.

    Returns:
        str: Formatted prompt string.
    """
    ip = device_info.get("ip", "unknown")
    status = device_info.get("status", "unknown")
    confidence = device_info.get("confidence", 0.0)
    pps = device_info.get("pps", device_info.get("packets_per_sec", 0.0))
    ports = device_info.get("unique_ports", 0)

    prompt = (
        f"You are a network security analyst. A device at IP {ip} has been "
        f"flagged as {status} by an anomaly detection system.\n\n"
        f"Device statistics:\n"
        f"- Packets per second: {pps}\n"
        f"- Unique destination ports contacted: {ports}\n"
        f"- Anomaly confidence score: {confidence}\n\n"
        f"Explain in plain English (2-3 sentences) what this means from a "
        f"security perspective. Include what the device might be doing and "
        f"what action a network administrator should take."
    )
    return prompt


# ---------------------------------------------------------------------------
# Fallback explanation
# ---------------------------------------------------------------------------

def _build_fallback(device_info: dict) -> str:
    """Generate a deterministic fallback explanation when Ollama is unavailable.

    Args:
        device_info: Dictionary with device statistics.

    Returns:
        str: A human-readable fallback explanation.
    """
    ip = device_info.get("ip", "unknown")
    status = device_info.get("status", "UNKNOWN")
    pps = device_info.get("pps", device_info.get("packets_per_sec", 0.0))
    ports = device_info.get("unique_ports", 0)

    reasons: list[str] = []
    if pps > 10:
        reasons.append("high packet rate")
    if ports > 10:
        reasons.append("port scanning activity")
    if status == "ROGUE":
        reasons.append("anomalous traffic patterns")

    if not reasons:
        reasons.append("unusual network behaviour")

    reason_str = ", ".join(reasons)
    return (
        f"AI analysis unavailable - Ollama not running. "
        f"Device {ip} shows anomalous behavior based on: {reason_str}."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def explain_threat(device_info: dict) -> str:
    """Generate a plain-English explanation of a detected threat.

    Sends the device anomaly statistics to a locally-running Ollama
    instance and returns the LLM's explanation.  If Ollama is not
    reachable, a deterministic fallback message is returned instead.

    Args:
        device_info: Dictionary containing device classification results.
            Expected keys: ``ip``, ``status``, ``confidence``,
            ``packets_per_sec``, ``unique_ports``.

    Returns:
        str: Human-readable security explanation (2–3 sentences).
    """
    prompt = _build_prompt(device_info)

    print(f"[explainer] Requesting AI explanation for {device_info.get('ip', '?')} ...")

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": True,
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        response.raise_for_status()

        # Ollama streams one JSON object per line, each with a 'response'
        # field containing a token fragment.
        explanation_parts: list[str] = []
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                chunk = json.loads(line)
                token = chunk.get("response", "")
                explanation_parts.append(token)
                # Optional: live-print tokens for demo effect
                print(token, end="", flush=True)
                if chunk.get("done", False):
                    break
            except json.JSONDecodeError:
                continue

        print()  # newline after streamed output
        explanation = "".join(explanation_parts).strip()

        if not explanation:
            print("[explainer] WARNING: Empty response from Ollama - using fallback.")
            return _build_fallback(device_info)

        print(f"[explainer] AI explanation received ({len(explanation)} chars).")
        return explanation

    except requests.exceptions.ConnectionError:
        print("[explainer] WARNING: Cannot connect to Ollama - is it running?")
        return _build_fallback(device_info)

    except requests.exceptions.Timeout:
        print(f"[explainer] WARNING: Ollama request timed out after {REQUEST_TIMEOUT}s.")
        return _build_fallback(device_info)

    except requests.exceptions.HTTPError as exc:
        print(f"[explainer] WARNING: Ollama returned HTTP error - {exc}")
        return _build_fallback(device_info)

    except Exception as exc:
        print(f"[explainer] ERROR: Unexpected error - {exc}")
        return _build_fallback(device_info)


# ---------------------------------------------------------------------------
# Main — quick demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_device = {
        "ip": "192.168.1.99",
        "status": "ROGUE",
        "confidence": -0.42,
        "packets_per_sec": 150.0,
        "unique_ports": 500,
    }
    print("[explainer] Running demo with sample device data...\n")
    result = explain_threat(sample_device)
    print(f"\n--- Explanation ---\n{result}\n")
