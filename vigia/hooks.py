"""
VIGÍA — Hook System
Event-driven hooks for the attack pipeline.
Decouples evaluation, logging, and side effects from the core attack loop.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class HookEvent(Enum):
    """Events emitted during attack execution."""
    # Campaign lifecycle
    CAMPAIGN_START = "campaign_start"
    CAMPAIGN_END = "campaign_end"

    # Attack lifecycle
    PRE_ATTACK = "pre_attack"           # Before sending prompt to target
    POST_ATTACK = "post_attack"         # After receiving response from target
    POST_EVALUATE = "post_evaluate"     # After evaluator scores the response

    # Agent-specific
    PRE_TOOL_USE = "pre_tool_use"       # Before agent calls a tool
    POST_TOOL_USE = "post_tool_use"     # After tool returns result

    # Multi-turn
    TURN_COMPLETE = "turn_complete"     # After each conversation turn


@dataclass
class HookContext:
    """Context passed to hook callbacks."""
    event: HookEvent
    campaign_id: Optional[int] = None
    seed: Optional[dict] = None
    prompt: Optional[str] = None
    response: Optional[str] = None
    score: Optional[int] = None
    evaluation: Optional[dict] = None
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    tool_result: Optional[Any] = None
    turn: Optional[int] = None
    target_model: Optional[str] = None
    metadata: dict = field(default_factory=dict)


# Type alias for hook callbacks
HookCallback = Callable[[HookContext], Optional[HookContext]]


class HookRegistry:
    """
    Central registry for hooks. Modules register callbacks for events,
    the pipeline fires them at the right time.

    Usage:
        registry = HookRegistry()

        @registry.on(HookEvent.POST_ATTACK)
        def log_response(ctx: HookContext) -> None:
            print(f"Got response: {ctx.response[:100]}")

        # Or register programmatically
        registry.register(HookEvent.POST_EVALUATE, my_callback)

        # Fire from pipeline
        registry.fire(HookEvent.POST_ATTACK, HookContext(
            event=HookEvent.POST_ATTACK,
            prompt="...",
            response="...",
        ))
    """

    def __init__(self):
        self._hooks: dict[HookEvent, list[HookCallback]] = {
            event: [] for event in HookEvent
        }

    def register(self, event: HookEvent, callback: HookCallback) -> None:
        """Register a callback for an event."""
        self._hooks[event].append(callback)

    def on(self, event: HookEvent) -> Callable:
        """Decorator to register a hook callback."""
        def decorator(fn: HookCallback) -> HookCallback:
            self.register(event, fn)
            return fn
        return decorator

    def fire(self, event: HookEvent, ctx: HookContext) -> HookContext:
        """
        Fire all callbacks for an event.
        Callbacks can modify the context (e.g., enrich metadata).
        Errors in callbacks are logged but never propagated.
        Returns the (possibly modified) context.
        """
        import logging
        _logger = logging.getLogger(__name__)
        for callback in self._hooks[event]:
            try:
                result = callback(ctx)
                if result is not None:
                    ctx = result
            except Exception as e:
                _logger.warning(f"Hook error on {event.value}: {e}")
        return ctx

    def clear(self, event: Optional[HookEvent] = None) -> None:
        """Clear hooks for a specific event, or all hooks."""
        if event:
            self._hooks[event] = []
        else:
            for e in HookEvent:
                self._hooks[e] = []


# ─── Built-in Hooks ─────────────────────────────────────────


def make_learning_hook(conn, campaign_id: int, target_model: str, threshold: int = 5) -> HookCallback:
    """
    Creates a POST_EVALUATE hook that records learnings to the DB.
    Connects the hook system to the session memory.
    """
    from vigia.database import record_learning

    def _record(ctx: HookContext) -> None:
        if ctx.score is not None and ctx.seed:
            record_learning(
                conn=conn,
                campaign_id=campaign_id,
                target_model=target_model,
                result={
                    "seed_id": ctx.seed.get("id", "unknown"),
                    "vector": ctx.seed.get("vector", "unknown"),
                    "score": ctx.score,
                    "language": ctx.seed.get("language"),
                    "owasp": ctx.seed.get("owasp") or ctx.seed.get("owasp_agentic"),
                },
                threshold=threshold,
            )
    return _record


def make_log_hook(verbose: bool = False) -> HookCallback:
    """Creates a POST_ATTACK hook that logs responses."""
    def _log(ctx: HookContext) -> None:
        if verbose and ctx.response:
            print(f"  [hook:log] {ctx.seed.get('id', '?')}: {ctx.response[:80]}...")
    return _log
