"""Workaround for DeepSeek's reasoning_content requirement.

DeepSeek v4 thinking-mode chat models return `reasoning_content` in the
assistant message; subsequent turns MUST echo it back or the API 400s with
"The `reasoning_content` in the thinking mode must be passed back to the API."

`langchain-openai` doesn't currently preserve `reasoning_content` when
serializing an AIMessage back to the chat-completions wire format, so any
multi-turn agent loop dies after the first assistant turn.

This module monkey-patches `_convert_message_to_dict` (the function langchain
uses to turn an AIMessage back into a dict) so it also includes
`reasoning_content` when present in the message's `additional_kwargs`. The
patch is idempotent and safe to apply multiple times.

Activate by calling `apply()` once before constructing `ChatOpenAI`.
"""

from __future__ import annotations


_APPLIED = False


def apply() -> None:
    global _APPLIED
    if _APPLIED:
        return
    try:
        from langchain_openai.chat_models import base as oc_base
    except ImportError:
        return  # langchain-openai not installed; nothing to patch

    original = oc_base._convert_message_to_dict

    def patched(message):
        out = original(message)
        # AIMessage subclasses may stash reasoning_content in additional_kwargs
        # (langchain-openai's _convert_chunk_to_generation_chunk preserves it on
        # the way IN). We need to mirror it on the way back OUT.
        ak = getattr(message, "additional_kwargs", None) or {}
        rc = ak.get("reasoning_content")
        if rc and out.get("role") == "assistant" and "reasoning_content" not in out:
            out["reasoning_content"] = rc
        return out

    oc_base._convert_message_to_dict = patched
    _APPLIED = True
