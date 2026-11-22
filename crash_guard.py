#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGY & Claude Code Crash Guard + Instant Root-Cause Doctor (v2.0 Full Professional Edition)
Author: HM Shihabuddin Jashory (Shihab) — Vision Flow (https://visionflowgroup.com)
License: MIT

Capabilities:
1. PreToolUse Firewall (Antigravity `read_file`/`view_file` & Claude Code `Read`):
   - Hard-blocks (`deny`) reading Password-Protected / Encrypted PDFs before they attach
     as raw `application/pdf` binaries into `transcript.jsonl` and cause permanent
     `HTTP 400 INVALID_ARGUMENT` trajectory poisoning.
   - Hard-blocks 0-byte, corrupted, or fake-extension media files (e.g. HTML/JSON login pages
     saved as `.pdf`/`.png`/`.jpg`).
   - Hard-blocks reading raw high-res images > 450 KB via `read_file` so repeated image
     inspections NEVER push the conversation request payload over the 30.000 MB hard limit
     (`FAILED_PRECONDITION (code 400): The message size exceeds 30.000MB limit`).
2. Post-Edit Practical Verification Gate (`Stop` / `ClaudeStop`):
   - Prevents agents from claiming "100% Done" after editing code if no verification command
     was executed in that turn (loop-safe: triggers at most once per user turn).
3. PreInvocation / Stop Hook & Real-Time Log Daemon (`language_server.log`):
   - Automatically detects `errorreport.go` executor crashes (`30.000MB limit`, `400 INVALID_ARGUMENT`,
     `blocked by content safety filters`, `429`, `500`, etc.) or repeated `/goal` stop-hook loops.
   - Immediately pops up a non-blocking Dark-Mode Diagnostic Window (English & Bangla support)
     with auto-clipboard copy of the recovery prompt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")

HOME_DIR = os.path.expanduser("~")
PYTHON_EXE = sys.executable
PYTHONW_EXE = sys.executable
if platform.system() == "Windows":
    cand_w = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if os.path.exists(cand_w):
        PYTHONW_EXE = cand_w

STATE_DIR = os.environ.get("AGY_CRASH_GUARD_STATE") or os.path.join(
    tempfile.gettempdir(), "agy_crash_guard"
)
BRAIN_ROOT = os.environ.get("AGY_BRAIN_ROOT") or os.path.join(
    HOME_DIR, ".gemini", "antigravity", "brain"
)

if platform.system() == "Windows":
    APPDATA = os.environ.get("APPDATA") or os.path.join(HOME_DIR, "AppData", "Roaming")
    DEFAULT_LOG = os.path.join(APPDATA, "Antigravity", "logs", "language_server.log")
elif platform.system() == "Darwin":
    DEFAULT_LOG = os.path.join(
        HOME_DIR, "Library", "Application Support", "Antigravity", "logs", "language_server.log"
    )
else:
    DEFAULT_LOG = os.path.join(HOME_DIR, ".config", "Antigravity", "logs", "language_server.log")

LANG_SERVER_LOG = os.environ.get("AGY_LANG_SERVER_LOG") or DEFAULT_LOG
UI_LANG = os.environ.get("AGY_CRASH_GUARD_LANG", "en").lower()

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ico"}
MULTIMODAL_EXTS = IMAGE_EXTS | {
    ".pdf", ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".mp4", ".mov", ".webm", ".avi"
}
CODE_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".html", ".css", ".scss", ".dart", ".go", ".rs", ".java", ".kt"
}
MAX_IMAGE_READ_KB = float(os.environ.get("AGY_MAX_IMAGE_KB", "450.0"))
MAX_BINARY_MB = float(os.environ.get("AGY_MAX_BINARY_MB", "10.0"))
MAX_PDF_PAGES = int(os.environ.get("AGY_MAX_PDF_PAGES", "60"))


def normalize_path(raw_path: str) -> str:
    if not raw_path:
        return ""
    p = raw_path.strip()
    if p.startswith("file:///"):
        p = urllib.parse.unquote(p[len("file:///"):])
        if platform.system() != "Windows" and not p.startswith("/"):
            p = "/" + p
    elif p.startswith("file://"):
        p = urllib.parse.unquote(p[len("file://"):])
    p = os.path.expandvars(os.path.expanduser(p))
    return os.path.normpath(p)


def looks_like_text_or_html(header: bytes) -> tuple[bool, str]:
    stripped = header.lstrip()
    lower = stripped[:200].lower()
    for prefix, label in [
        (b"<!doctype html", "HTML Document (<!DOCTYPE html>)"),
        (b"<html", "HTML Page (<html>)"),
        (b"<?xml", "XML / SVG Document"),
        (b"{\"error\"", "JSON Error Object"),
        (b"{", "JSON Object"),
        (b"accessdenied", "AccessDenied Response"),
        (b"404 not found", "404 Not Found Text"),
        (b"403 forbidden", "403 Forbidden Text"),
    ]:
        if lower.startswith(prefix):
            preview = stripped[:160].decode("utf-8", errors="replace").replace("\n", " ")
            return True, f"{label} -> Preview: {preview}"
    return False, ""


def inspect_file_for_read_tool(file_path: str, strict_image_cap: bool = True) -> tuple[bool, str]:
    path = normalize_path(file_path)
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return True, ""

    ext = os.path.splitext(path)[1].lower()
    if ext not in MULTIMODAL_EXTS:
        return True, ""

    try:
        size_bytes = os.path.getsize(path)
    except OSError:
        return True, ""

    size_kb = size_bytes / 1024.0
    size_mb = size_bytes / (1024.0 * 1024.0)

    # 1. Zero-byte binary/media file check
    if size_bytes == 0:
        return False, (
            f"🚫 [AGY CRASH GUARD — BLOCKED 0-BYTE MEDIA FILE]: '{path}' is 0 bytes (empty). "
            f"Calling read_file/Read on an empty {ext} file attaches an invalid '{ext}' binary to transcript.jsonl "
            f"and causes a permanent HTTP 400 INVALID_ARGUMENT crash."
        )

    try:
        with open(path, "rb") as f:
            header = f.read(1024)
    except OSError:
        return True, ""

    # 2. Fake binary check (HTML/JSON/text saved with media extension)
    is_fake_text, fake_desc = looks_like_text_or_html(header)
    if is_fake_text:
        return False, (
            f"🚫 [AGY CRASH GUARD — BLOCKED CORRUPTED/FAKE '{ext.upper()}' FILE]: '{path}' has extension '{ext}', "
            f"but its contents are actually plain text/HTML ({fake_desc}). "
            f"Do NOT use read_file/Read on it; inspect it with Python via terminal."
        )

    # 3. High-Res Image Guard (> 450 KB) to prevent 30.000MB message size limit crash
    if strict_image_cap and ext in IMAGE_EXTS and size_kb > MAX_IMAGE_READ_KB:
        return False, (
            f"🚫 [AGY CRASH GUARD — BLOCKED LARGE IMAGE READ ({size_kb:.0f} KB > {MAX_IMAGE_READ_KB:.0f} KB CAP)]: "
            f"'{path}' is {size_kb:.0f} KB ({size_mb:.2f} MB). Calling read_file/Read on large PNG/JPG files embeds "
            f"multi-megabyte blobs into transcript.jsonl on every turn and triggers 'FAILED_PRECONDITION (code 400): "
            f"The message size exceeds 30.000MB limit'.\n"
            f"✅ SAFE WORKAROUND: Use Python PIL/Pillow in the terminal to save a compressed JPEG preview "
            f"(< 120 KB, max 960px width, quality=72) in your temp directory and read that small preview instead."
        )

    # 4. General Oversized Binary Check (> 10 MB)
    if size_mb > MAX_BINARY_MB:
        return False, (
            f"🚫 [AGY CRASH GUARD — BLOCKED OVERSIZED MEDIA ({size_mb:.1f} MB > {MAX_BINARY_MB} MB)]: '{path}' is too large "
            f"for multimodal read_file and will exceed the 30.000MB API message limit. Process it via terminal."
        )

    # 5. PDF-Specific Checks (Magic Header + Password Encryption + Page Count)
    if ext == ".pdf":
        if b"%PDF-" not in header[:1024]:
            return False, (
                f"🚫 [AGY CRASH GUARD — INVALID PDF HEADER]: '{path}' does not start with a valid '%PDF-' header. "
                f"Do NOT call read_file/Read on it."
            )
        is_enc = False
        page_count = -1
        try:
            with open(path, "rb") as pf:
                raw_pdf = pf.read(min(size_bytes, 512_000))
            if re.search(rb"/Encrypt\b", raw_pdf):
                is_enc = True
        except OSError:
            pass

        if not is_enc:
            try:
                import pymupdf  # PyMuPDF
                doc = pymupdf.open(path)
                is_enc = bool(doc.is_encrypted)
                page_count = len(doc) if not is_enc else -1
                doc.close()
            except ImportError:
                pass
            except Exception as e:
                return False, (
                    f"🚫 [AGY CRASH GUARD — CORRUPTED/UNREADABLE PDF]: PyMuPDF failed to open '{path}' ({e}). "
                    f"Calling read_file on a damaged PDF causes permanent HTTP 400 INVALID_ARGUMENT crashes."
                )

        if is_enc:
            return False, (
                f"🚫 [AGY CRASH GUARD — BLOCKED PASSWORD-ENCRYPTED PDF]: '{path}' is PASSWORD-PROTECTED "
                f"(doc.is_encrypted == True). Calling `read_file`/`Read` on an encrypted PDF attaches a locked binary "
                f"to `transcript.jsonl` and permanently crashes the conversation with `HTTP 400 INVALID_ARGUMENT`.\n"
                f"✅ SAFE WORKAROUND: Use Python (`import pymupdf; doc = pymupdf.open(r'{path}'); "
                f"doc.authenticate(PASSWORD)`) in the terminal to extract text or render unlocked pages."
            )

        if page_count > MAX_PDF_PAGES:
            return False, (
                f"🚫 [AGY CRASH GUARD — PDF TOO MANY PAGES ({page_count} pages > {MAX_PDF_PAGES})]: '{path}' has "
                f"{page_count} pages. Extract specific pages or text using Python `pymupdf` in the terminal."
            )

    # 6. Image header sanity check
    if ext == ".png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, f"🚫 [AGY CRASH GUARD — INVALID PNG HEADER]: '{path}' does not have a valid PNG signature."
    if ext in (".jpg", ".jpeg") and not header.startswith(b"\xff\xd8\xff"):
        return False, f"🚫 [AGY CRASH GUARD — INVALID JPEG HEADER]: '{path}' does not have a valid JPEG signature."

    return True, ""


def extract_tool_file_path(payload: dict) -> tuple[str, str]:
    tc = payload.get("toolCall") or {}
    if isinstance(tc, dict) and tc.get("name"):
        name = str(tc.get("name") or "")
        args = tc.get("args") or {}
        if isinstance(args, dict):
            for k in ("Path", "path", "file_path", "AbsolutePath", "File", "TargetFile"):
                if args.get(k):
                    return name, str(args[k])
    tname = str(payload.get("tool_name") or "")
    tinput = payload.get("tool_input") or {}
    if isinstance(tinput, dict):
        for k in ("file_path", "path", "Path"):
            if tinput.get(k):
                return tname, str(tinput[k])
    return "", ""


def log_guard_event(event_type: str, conv_id: str, detail: str) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(os.path.join(STATE_DIR, "guard_events.log"), "a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [{event_type}] [conv={conv_id}] {detail}\n")
    except Exception:
        pass


def _deny_pre_tool(is_claude: bool, conv_id: str, reason: str) -> None:
    log_guard_event("BLOCKED_PRE_TOOL", conv_id, reason)
    if is_claude:
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        print(json.dumps(out, ensure_ascii=False))
    else:
        print(json.dumps({"decision": "deny", "reason": reason}, ensure_ascii=False))


def handle_pre_tool_use(is_claude: bool = False) -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print(json.dumps({} if is_claude else {"decision": "allow"}))
        return

    conv_id = str(payload.get("conversationId") or payload.get("session_id") or "")
    tool_name, file_path = extract_tool_file_path(payload)

    if file_path and tool_name.lower() in ("read_file", "view_file", "read"):
        allowed, reason = inspect_file_for_read_tool(file_path, strict_image_cap=True)
        if not allowed:
            _deny_pre_tool(is_claude, conv_id, reason)
            return

    print(json.dumps({} if is_claude else {"decision": "allow"}))


def evaluate_stop_verification_gate(payload: dict) -> tuple[bool, str]:
    """
    Loop-safe Stop Gate: If code files were modified in the latest turn without any
    verification command run afterwards, prompts the agent ONCE per turn to verify its changes.
    """
    conv_id = str(payload.get("conversationId") or payload.get("session_id") or "default")
    transcript_path = str(payload.get("transcriptPath") or payload.get("transcript_path") or "")
    if not transcript_path and conv_id and os.path.isdir(BRAIN_ROOT):
        cand = os.path.join(BRAIN_ROOT, conv_id, ".system_generated", "logs", "transcript.jsonl")
        if os.path.exists(cand):
            transcript_path = cand

    if not transcript_path or not os.path.exists(transcript_path):
        return False, ""

    try:
        with open(transcript_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            fsize = f.tell()
            f.seek(max(0, fsize - 200_000))
            lines = f.read().decode("utf-8", errors="replace").splitlines()[-50:]
    except Exception:
        return False, ""

    last_user_step = -1
    edited_code_files = []
    verified_after_edit = False

    for line in lines:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        step_idx = obj.get("step_index", -1)
        if obj.get("type") == "USER_INPUT":
            last_user_step = step_idx
            edited_code_files = []
            verified_after_edit = False
            continue

        for tc in (obj.get("tool_calls") or []):
            if not isinstance(tc, dict):
                continue
            tname = str(tc.get("name") or "").lower()
            targs = tc.get("args") or {}
            if tname in ("write_file", "edit_file", "write", "edit", "multiedit"):
                p = str(targs.get("Path") or targs.get("file_path") or targs.get("path") or "")
                ext = os.path.splitext(p)[1].lower()
                if ext in CODE_EXTENSIONS:
                    edited_code_files.append(os.path.basename(p))
                    verified_after_edit = False
            elif tname in ("run_command", "bash", "call_mcp_tool"):
                if edited_code_files:
                    verified_after_edit = True

    if not edited_code_files or verified_after_edit:
        return False, ""

    os.makedirs(STATE_DIR, exist_ok=True)
    state_file = os.path.join(STATE_DIR, "stop_gate_state.json")
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}

    gate_key = f"{conv_id}:{last_user_step}"
    if state.get(gate_key):
        return False, ""

    state[gate_key] = True
    try:
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass

    files_str = ", ".join(sorted(set(edited_code_files))[:4])
    return True, (
        f"[PRACTICAL VERIFICATION GATE]: You modified code ({files_str}) in this turn without running "
        f"any verification command or test afterwards. Run a practical test to verify your changes before finishing."
    )


def get_recent_lang_server_errors(tail_lines: int = 300) -> tuple[list[str], str]:
    if not os.path.exists(LANG_SERVER_LOG):
        return [], ""
    try:
        with open(LANG_SERVER_LOG, "rb") as f:
            f.seek(0, os.SEEK_END)
            fsize = f.tell()
            read_size = min(fsize, 250_000)
            f.seek(max(0, fsize - read_size))
            lines = f.read().decode("utf-8", errors="replace").splitlines()[-tail_lines:]
    except Exception:
        return [], ""

    errors = []
    latest_conv = ""
    conv_re = re.compile(r'(?:root_conversation_id|cascade_id)[=:]"?([0-9a-fA-F-]{36})"?')
    for line in lines:
        m = conv_re.search(line)
        if m:
            latest_conv = m.group(1)
        if any(
            k in line
            for k in (
                "errorreport.go",
                "agent executor error",
                "INVALID_ARGUMENT",
                "FAILED_PRECONDITION",
                "RESOURCE_EXHAUSTED",
                "blocked by content safety filters",
            )
        ):
            errors.append(line.strip())
    return errors, latest_conv


def clean_log_snippet(raw_line: str) -> str:
    if "errorreport.go:" in raw_line:
        parts = raw_line.split("errorreport.go:", 1)[-1]
        idx = parts.find("]")
        if idx != -1:
            return parts[idx + 1:].strip()
    return raw_line[-220:].strip()


def diagnose_conversation(conv_id: str = "", raw_error: str = "", transcript_override: str = "") -> dict | None:
    errors, detected_conv = get_recent_lang_server_errors()
    if not conv_id:
        conv_id = detected_conv
    if not conv_id and os.path.isdir(BRAIN_ROOT):
        candidates = []
        for d in os.listdir(BRAIN_ROOT):
            tp = os.path.join(BRAIN_ROOT, d, ".system_generated", "logs", "transcript.jsonl")
            if os.path.exists(tp):
                candidates.append((os.path.getmtime(tp), d))
        if candidates:
            candidates.sort(reverse=True)
            conv_id = candidates[0][1]

    last_err_line = raw_error or (errors[-1] if errors else "Unknown Agent Executor Error")
    short_err = clean_log_snippet(last_err_line)
    transcript_path = transcript_override or (
        os.path.join(BRAIN_ROOT, conv_id, ".system_generated", "logs", "transcript.jsonl") if conv_id else ""
    )

    poisoned_media = []
    stop_hook_loops = 0
    total_media_mb = 0.0

    if transcript_path and os.path.exists(transcript_path):
        try:
            with open(transcript_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                fsize = f.tell()
                f.seek(max(0, fsize - 280_000))
                raw_lines = f.read().decode("utf-8", errors="replace").splitlines()[-60:]
        except Exception:
            raw_lines = []

        active_steps = []
        for rline in raw_lines:
            try:
                obj = json.loads(rline)
            except Exception:
                continue
            step_idx = obj.get("step_index")
            if isinstance(step_idx, int):
                active_steps = [prev for prev in active_steps if (prev.get("step_index") or -1) < step_idx]
            active_steps.append(obj)

        for obj in active_steps:
            step_idx = obj.get("step_index")
            content = str(obj.get("content") or "")
            if "Stop hook blocked termination" in content:
                stop_hook_loops += 1

            for m in (obj.get("media") or []):
                if not isinstance(m, dict):
                    continue
                uri = str(m.get("uri") or "")
                mime = str(m.get("mime_type") or "")
                fpath = normalize_path(uri)
                if fpath and os.path.exists(fpath):
                    try:
                        total_media_mb += os.path.getsize(fpath) / (1024.0 * 1024.0)
                    except OSError:
                        pass
                    allowed, deny_reason = inspect_file_for_read_tool(fpath, strict_image_cap=False)
                    if not allowed:
                        poisoned_media.append({
                            "step": step_idx,
                            "mime": mime,
                            "path": fpath,
                            "reason": deny_reason,
                        })

    size_match = re.search(r"message size \((\d+) bytes\) exceeds ([\d.]+MB) limit", last_err_line, re.I)
    if size_match or "exceeds 30.000MB limit" in last_err_line or "message size" in last_err_line.lower():
        actual_mb = int(size_match.group(1)) / (1024 * 1024) if size_match else 30.5
        limit_str = size_match.group(2) if size_match else "30.000MB"
        title = f"Conversation Payload Exceeded {limit_str} Limit ({actual_mb:.1f} MB)!"
        why = (
            f"1. The agent read multiple large images (PNG/JPG) directly into the conversation context.\n"
            f"2. Cumulative request size reached {actual_mb:.2f} MB, exceeding the {limit_str} server cap.\n"
            f"3. PreToolUse Guard now blocks images > {MAX_IMAGE_READ_KB:.0f} KB automatically."
        )
        solution = (
            "1. Type /compact in the chat box to compress older image payloads, OR\n"
            "2. Undo the last message and paste the ready recovery prompt below."
        )
        fix_prompt = (
            "The conversation request size is near the 30MB limit. Do NOT open any raw images with read_file/Read; "
            "use terminal scripts to inspect or compress images first."
        )
    elif poisoned_media:
        first_bad = poisoned_media[-1]
        bad_step = first_bad["step"]
        bad_name = os.path.basename(first_bad["path"])
        is_enc_pdf = "PASSWORD-ENCRYPTED PDF" in first_bad["reason"]
        if is_enc_pdf:
            title = f"Password-Protected PDF Poisoned Trajectory (Step #{bad_step})"
            why = (
                f"1. At Step #{bad_step}, the agent called read_file/Read on a password-encrypted PDF ({bad_name}).\n"
                f"2. LLM APIs cannot parse locked PDF binaries and reject the entire trajectory with HTTP 400 INVALID_ARGUMENT."
            )
            fix_prompt = (
                f"Do NOT call read_file/Read on the password-protected PDF ({bad_name}) from Step #{bad_step}. "
                f"Use Python `pymupdf` with `doc.authenticate(password)` in the terminal instead."
            )
        else:
            title = f"Corrupted or Fake-Header Media File Poisoned Trajectory (Step #{bad_step})"
            why = f"1. At Step #{bad_step}, the agent read '{bad_name}'.\n2. Issue: {first_bad['reason']}"
            fix_prompt = f"Do NOT open '{bad_name}' directly with read_file/Read; inspect it via Python in the terminal."
        solution = (
            f"1. Scroll to the message before Step #{bad_step} and click Undo.\n"
            f"2. Paste the auto-copied recovery prompt below."
        )
    else:
        title = "Agent Execution Terminated (Backend API Error)"
        why = f"1. Backend error: {short_err}"
        solution = "1. Undo the last turn or retry with the recovery prompt below."
        fix_prompt = "Continue the task safely using terminal tools without reading large binary or media files."

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "conversation_id": conv_id,
        "raw_error": short_err,
        "title": title,
        "why": why,
        "solution": solution,
        "fix_prompt": fix_prompt,
        "poisoned_media": poisoned_media,
    }


def write_diagnosis_report(diag: dict) -> str:
    os.makedirs(STATE_DIR, exist_ok=True)
    conv_id = diag.get("conversation_id") or "unknown"
    md = (
        f"# 🚨 Instant Crash Diagnosis Report\n\n"
        f"- **Time:** `{diag['timestamp']}`\n"
        f"- **Conversation ID:** `{conv_id}`\n"
        f"- **Backend Error:** `{diag['raw_error']}`\n\n"
        f"## 🔍 {diag['title']}\n\n"
        f"### Root Cause:\n{diag['why']}\n\n"
        f"### How To Fix:\n{diag['solution']}\n\n"
        f"### Ready Recovery Prompt:\n```text\n{diag['fix_prompt']}\n```\n"
    )
    latest_path = os.path.join(STATE_DIR, "latest_crash_diagnosis.md")
    try:
        with open(latest_path, "w", encoding="utf-8") as f:
            f.write(md)
    except Exception:
        pass
    return latest_path


def show_popup_window(payload_file: str | dict) -> None:
    if isinstance(payload_file, dict):
        diag = payload_file
    else:
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                diag = json.load(f)
        except Exception:
            return

    try:
        import tkinter as tk
    except Exception:
        return

    root = tk.Tk()
    root.title("Agent Crash Doctor — Instant Root-Cause & Recovery")
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    win_w = min(840, int(sw * 0.72))
    win_h = min(620, int(sh * 0.74))
    pos_x = max(20, (sw - win_w) // 2)
    pos_y = max(20, (sh - win_h) // 2)
    root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
    root.configure(bg="#0f172a")
    root.attributes("-topmost", True)

    ui_font = "Segoe UI" if platform.system() == "Windows" else "Sans"
    mono_font = "Consolas"

    hdr = tk.Frame(root, bg="#1e293b", padx=18, pady=10)
    hdr.pack(fill="x", side="top")
    tk.Label(
        hdr,
        text=f"⚠️ {diag.get('title', 'Agent Execution Error Detected')}",
        fg="#f87171",
        bg="#1e293b",
        font=(ui_font, 13, "bold"),
        anchor="w",
    ).pack(fill="x")

    fix_prompt = diag.get("fix_prompt", "Continue safely without reading raw binary files.")
    try:
        root.clipboard_clear()
        root.clipboard_append(fix_prompt)
        root.update()
    except Exception:
        pass

    btn_frame = tk.Frame(root, bg="#0f172a", padx=18, pady=8)
    btn_frame.pack(fill="x", side="top")
    status_lbl = tk.Label(
        btn_frame,
        text="✅ Recovery Prompt Auto-Copied to Clipboard! (Press Ctrl+V in chat)",
        fg="#4ade80",
        bg="#0f172a",
        font=(ui_font, 10, "bold"),
    )

    def copy_fix():
        root.clipboard_clear()
        root.clipboard_append(fix_prompt)
        root.update()
        status_lbl.configure(text="✅ Copied to Clipboard!")

    tk.Button(
        btn_frame,
        text="📋 Copy Recovery Prompt",
        command=copy_fix,
        bg="#2563eb",
        fg="#ffffff",
        relief="flat",
        padx=14,
        pady=5,
        font=(ui_font, 10, "bold"),
    ).pack(side="left")
    status_lbl.pack(side="left", padx=12)
    tk.Button(
        btn_frame,
        text="Close",
        command=root.destroy,
        bg="#334155",
        fg="#f8fafc",
        relief="flat",
        padx=12,
        pady=5,
        font=(ui_font, 10),
    ).pack(side="right")

    body_frame = tk.Frame(root, bg="#0f172a", padx=18, pady=6)
    body_frame.pack(fill="both", expand=True, side="top")
    txt = tk.Text(body_frame, bg="#0b1120", fg="#f1f5f9", font=(ui_font, 11), wrap="word", padx=16, pady=12)
    txt.pack(fill="both", expand=True)
    txt.insert("end", f"1. Root Cause:\n{diag.get('why', '')}\n\n")
    txt.insert("end", f"2. How To Fix:\n{diag.get('solution', '')}\n\n")
    txt.insert("end", f"3. Ready Recovery Prompt:\n{fix_prompt}\n\n")
    txt.insert("end", f"4. Backend Error:\n{diag.get('raw_error', 'N/A')}\n")
    root.mainloop()


def handle_stop_hook(is_claude: bool = False) -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print(json.dumps({} if is_claude else {"decision": "allow"}))
        return

    reason = str(payload.get("terminationReason") or "")
    conv_id = str(payload.get("conversationId") or payload.get("session_id") or "")
    err_str = str(payload.get("error") or "")

    if reason == "ERROR" or err_str:
        diag = diagnose_conversation(conv_id, err_str)
        if diag:
            write_diagnosis_report(diag)
            log_guard_event("STOP_HOOK_CRASH_DETECTED", conv_id, diag.get("title", ""))
        print(json.dumps({} if is_claude else {"decision": "allow"}))
        return

    should_block, gate_reason = evaluate_stop_verification_gate(payload)
    if should_block and gate_reason:
        log_guard_event("STOP_GATE_ENFORCED", conv_id, gate_reason)
        if is_claude:
            print(json.dumps({"decision": "block", "reason": gate_reason}, ensure_ascii=False))
        else:
            print(json.dumps({"decision": "continue", "reason": gate_reason}, ensure_ascii=False))
        return

    print(json.dumps({} if is_claude else {"decision": "allow"}))


def main() -> None:
    parser = argparse.ArgumentParser(description="AGY & Claude Code Crash Guard (Full Edition)")
    parser.add_argument("--event", type=str, default="", help="Lifecycle event name")
    parser.add_argument("--diagnose", type=str, nargs="?", const="auto", help="Diagnose conversation ID")
    parser.add_argument("--diagnose-transcript", type=str, default="", help="Diagnose specific transcript.jsonl")
    parser.add_argument("--test-file", type=str, default="", help="Test file path against PreToolUse guard")
    parser.add_argument("--show-popup", type=str, default="", help="Show GUI popup from JSON file")
    parser.add_argument("--version", action="version", version="%(prog)s 2.1.1")
    args = parser.parse_args()

    if args.show_popup:
        show_popup_window(args.show_popup)
        return

    if args.test_file:
        allowed, reason = inspect_file_for_read_tool(args.test_file, strict_image_cap=True)
        print(json.dumps({"allowed": allowed, "reason": reason}, ensure_ascii=False, indent=2))
        return

    if args.diagnose_transcript:
        diag = diagnose_conversation(transcript_override=args.diagnose_transcript)
        print(json.dumps(diag, ensure_ascii=False, indent=2))
        return

    if args.diagnose:
        cid = "" if args.diagnose == "auto" else args.diagnose
        diag = diagnose_conversation(cid)
        if diag:
            report_path = write_diagnosis_report(diag)
            print(json.dumps({"report_path": report_path, "diagnosis": diag}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({"error": "No diagnosis available"}))
        return

    ev = args.event
    if ev == "PreToolUse":
        handle_pre_tool_use(is_claude=False)
    elif ev == "ClaudePreToolUse":
        handle_pre_tool_use(is_claude=True)
    elif ev == "Stop":
        handle_stop_hook(is_claude=False)
    elif ev == "ClaudeStop":
        handle_stop_hook(is_claude=True)
    else:
        print(json.dumps({"decision": "allow"}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"decision": "allow"}))
    sys.exit(0)
