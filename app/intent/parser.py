"""Deterministic Intent Parser for AEGIS-CORE.

==============================================================================
CRITICAL SECURITY INVARIANTS:
------------------------------------------------------------------------------
1. Deterministic and offline: Zero LLM, zero network, zero database calls.
2. Whitelisted supported intents:
   - READ_LATEST_EMAILS
   - SUMMARIZE_RECENT_EMAILS
   - SEARCH_EMAILS
   - READ_EMAIL_DETAILS
3. Reject unsupported actions: send, delete, modify, forward, export, execute.
4. Bound requested counts: strictly 1 to 20. Non-positive or excessive counts fail.
5. Fail-closed ambiguity: Ambiguous, compound, or vague requests return explicit
   clarification requirements or raise AmbiguousIntentError.
6. Least privilege: Never infer permissions beyond the explicit user prompt.
7. Language separation: response_language tracks presentation only, never authority.
==============================================================================
"""

import re
import unicodedata

from app.intent.exceptions import (
    AmbiguousIntentError,
    EmptyRequestError,
    IntentParsingError,
    InvalidCountError,
    UnsupportedIntentError,
)
from app.intent.schemas import (
    ActionType,
    IntentType,
    ResourceType,
    TaskIntent,
)

# Operational limits
MAX_REQUEST_LENGTH: int = 2000
MIN_ALLOWED_COUNT: int = 1
MAX_ALLOWED_COUNT: int = 20
MAX_QUERY_LENGTH: int = 200

# Mapping Eastern Arabic digits to standard ASCII digits
EASTERN_ARABIC_DIGITS: dict[str, str] = {
    "٠": "0",
    "١": "1",
    "٢": "2",
    "٣": "3",
    "٤": "4",
    "٥": "5",
    "٦": "6",
    "٧": "7",
    "٨": "8",
    "٩": "9",
}
EASTERN_DIGITS_TRANS = str.maketrans(EASTERN_ARABIC_DIGITS)

# Arabic diacritics (tashkeel) and tatweel removal
TASHKEEL_REGEX = re.compile(r"[\u0617-\u061A\u064B-\u0652\u0670]")
TATWEEL_REGEX = re.compile(r"\u0640")

# Prompt injection adversarial override signatures
INJECTION_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:ignore\s+(?:previous|all|above)\s+instructions|system\s*prompt|admin\s+override|developer\s+mode|jailbreak|disregard\s+(?:previous|safety))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:تجاهل\s+(?:التعليمات|الأوامر)\s+(?:السابقة|كلها)|تخطي\s+الأمان|وضع\s+المطور|صلاحيات\s+المسؤول)",
        re.IGNORECASE,
    ),
)

# Unsupported / forbidden action patterns
UNSUPPORTED_ACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "delete",
        re.compile(
            r"\b(?:delete|remove|erase|trash|drop|purge|wipe|destroy)\b|(?:احذف|امسح|إلغاء|الغاء|حذف|مسح|تخلص\s+من)",
            re.IGNORECASE,
        ),
    ),
    (
        "send",
        re.compile(
            r"\b(?:send|compose|dispatch|transmit|mail\s+to)\b|(?:أرسل|ارسل|ابعت|إرسال|ارسال)",
            re.IGNORECASE,
        ),
    ),
    (
        "modify",
        re.compile(
            r"\b(?:update|modify|edit|change|alter|overwrite|patch)\b|(?:عدل|غير|حرر|تعديل|تغيير)",
            re.IGNORECASE,
        ),
    ),
    (
        "forward",
        re.compile(
            r"\b(?:forward|redirect|route\s+to)\b|(?:حول|إعادة\s+توجيه|اعادة\s+توجيه|تحويل)",
            re.IGNORECASE,
        ),
    ),
    (
        "export",
        re.compile(
            r"\b(?:export|download|dump|exfiltrate|backup|extract)\b|(?:تصدير|نزل|حمل|تنزيل|تحميل|استخرج|استخراج)",
            re.IGNORECASE,
        ),
    ),
    (
        "draft",
        re.compile(
            r"\b(?:draft|compose)\b|(?:مسودة|اكتب\s+مسودة)",
            re.IGNORECASE,
        ),
    ),
    (
        "execute",
        re.compile(
            r"\b(?:exec|execute|shell|bash|powershell|cmd|eval|admin|grant|privilege)\b|(?:شغل|نفذ|أوامر|اوامر|شل|صلاحيات|ادمن)",
            re.IGNORECASE,
        ),
    ),
)

# Compound request indicators connecting multiple action phrases
COMPOUND_ACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:read|summarize|search|show|find|get)\b.+?\b(?:and|then|also|as\s+well\s+as|;)\s+(?:read|summarize|search|show|find|get|delete|send|modify)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:اقرأ|اقرا|لخص|أوجز|ابحث|اعرض|افتح|شوف).+?(?:\s+و\s*|\s*;\s*)(?:اقرأ|اقرا|لخص|أوجز|ابحث|اعرض|افتح|احذف|ارسل|أرسل)",
        re.IGNORECASE,
    ),
)


class DeterministicIntentParser:
    """Offline, deterministic natural-language intent parser for AEGIS-CORE."""

    def __init__(self) -> None:
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Precompile English and Arabic regex patterns for supported intents."""
        # Polite optional prefixes
        en_pref = r"^(?:(?:please|can\s+you|could\s+you)\s+)?"
        ar_pref = r"^(?:(?:من\s+فضلك|لو\s+سمحت|رجاء(?:ً)?|ممكن)\s+)?"
        end_punct = r"[\s.?؟]*$"

        # 1. SUMMARIZE RECENT EMAILS
        # English: "Summarize my latest 2 emails in Arabic."
        self.en_summarize = re.compile(
            en_pref
            + r"(?:summarize|give\s+me\s+a\s+summary\s+of)\s+(?:my\s+|the\s+)?(?:latest|recent)\s+(-?\d+)\s+emails?(?:\s+in\s+([a-zA-Z\u0600-\u06FF]+))?"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_summarize_alt = re.compile(
            en_pref
            + r"(?:summarize|give\s+me\s+a\s+summary\s+of)\s+(?:the\s+)?(-?\d+)\s+(?:latest|recent)\s+emails?(?:\s+in\s+([a-zA-Z\u0600-\u06FF]+))?"
            + end_punct,
            re.IGNORECASE,
        )
        # Arabic: "لخص آخر 3 إيميلات بالعربي."
        self.ar_summarize = re.compile(
            ar_pref
            + r"(?:لخص|أوجز|اوجز|اعطني\s+ملخص|قدم\s+ملخص|تلخيص)\s+(?:لي\s+)?(?:ل)?(?:آخر|اخر|أحدث|احدث)\s+(-?\d+)\s+(?:إيميلات|ايميلات|رسائل|ايميل|إيميل|رسالة)(?:\s+(بالعربي|باللغة\s+العربية|بالانجليزي|باللغة\s+الانجليزية|بالإنجليزي|باللغة\s+الإنجليزية))?"
            + end_punct,
            re.IGNORECASE,
        )

        # 2. READ LATEST EMAILS
        # English: "Read my latest 3 emails."
        self.en_read_latest = re.compile(
            en_pref
            + r"(?:read|get|show|fetch|list|view)\s+(?:my\s+|the\s+)?(?:most\s+)?(?:latest|recent)\s+(-?\d+)\s+emails?"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_read_latest_alt = re.compile(
            en_pref
            + r"(?:read|get|show|fetch|list|view)\s+(?:the\s+)?(-?\d+)\s+(?:latest|recent)\s+emails?"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_read_inbox_count = re.compile(
            en_pref
            + r"(?:read|check)\s+(?:my\s+)?inbox\s+(?:latest|recent)\s+(-?\d+)\s+emails?"
            + end_punct,
            re.IGNORECASE,
        )
        # Arabic: "اقرأ آخر 3 إيميلات."
        self.ar_read_latest = re.compile(
            ar_pref
            + r"(?:اقرأ|اقرا|اعرض|أرني|ارني|هات|جلب|استعرض|شوف)\s+(?:لي\s+)?(?:آخر|اخر|أحدث|احدث)\s+(-?\d+)\s+(?:إيميلات|ايميلات|رسائل|ايميل|إيميل|رسالة)"
            + end_punct,
            re.IGNORECASE,
        )

        # 3. SEARCH EMAILS
        # English: "Search emails for assignment."
        self.en_search = re.compile(
            en_pref
            + r"(?:search|find|look\s+for)\s+(?:my\s+)?emails\s+(?:for|about|with\s+keyword|containing)\s+['\"]?(.+?)['\"]?"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_search_in = re.compile(
            en_pref
            + r"search\s+(?:for\s+)?['\"]?(.+?)['\"]?\s+in\s+(?:my\s+)?emails?"
            + end_punct,
            re.IGNORECASE,
        )
        # Arabic: "ابحث عن إيميلات فيها كلمة امتحان."
        self.ar_search = re.compile(
            ar_pref
            + r"(?:ابحث|دور|فتش)\s+(?:عن|في)\s+(?:إيميلات|ايميلات|رسائل|الإيميلات|الايميلات|الرسائل|البريد)(?:\s+(?:فيها\s+كلمة|تحتوي\s+على|بخصوص|عن))?\s+['\"]?(.+?)['\"]?"
            + end_punct,
            re.IGNORECASE,
        )
        self.ar_search_in = re.compile(
            ar_pref
            + r"(?:ابحث\s+عن|دور\s+على|فتش\s+عن)\s+['\"]?(.+?)['\"]?\s+في\s+(?:الإيميلات|الايميلات|الرسائل|البريد)"
            + end_punct,
            re.IGNORECASE,
        )

        # 4. READ SPECIFIC EMAIL BY ID
        # English: "Show email 7."
        self.en_show_email = re.compile(
            en_pref
            + r"(?:show|read|get|view|open|display)\s+(?:me\s+)?email\s+(?:details\s+)?(?:#|number\s+|id\s+)?(-?\d+)"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_email_direct = re.compile(
            en_pref
            + r"email\s+(?:#|number\s+|id\s+)?(-?\d+)\s*(?:details)?"
            + end_punct,
            re.IGNORECASE,
        )
        # Arabic: "اعرض الإيميل رقم 7."
        self.ar_show_email = re.compile(
            ar_pref
            + r"(?:اعرض|اقرأ|اقرا|أرني|ارني|افتح|شوف|عرض|أظهر|اظهر)\s+(?:لي\s+)?(?:تفاصيل\s+)?(?:الإيميل|الايميل|الرسالة|إيميل|ايميل|رسالة)(?:\s+(?:رقم|#))?\s+(-?\d+)"
            + end_punct,
            re.IGNORECASE,
        )
        self.ar_email_direct = re.compile(
            ar_pref + r"(?:الإيميل|الايميل|الرسالة)\s+(?:رقم|#)\s+(-?\d+)" + end_punct,
            re.IGNORECASE,
        )

        # Ambiguous patterns requiring explicit clarification
        self.en_ambig_summarize = re.compile(
            en_pref + r"summarize\s+(?:my\s+)?emails?" + end_punct, re.IGNORECASE
        )
        self.en_ambig_read = re.compile(
            en_pref
            + r"(?:read|check|show|view|get|fetch)\s+(?:my\s+)?(?:emails?|inbox)"
            + end_punct,
            re.IGNORECASE,
        )
        self.en_ambig_search = re.compile(
            en_pref + r"(?:search|find|look\s+for)\s+(?:my\s+)?emails?" + end_punct,
            re.IGNORECASE,
        )
        self.en_ambig_show = re.compile(
            en_pref + r"(?:show|read|get|view|open)\s+(?:me\s+)?email" + end_punct,
            re.IGNORECASE,
        )

        self.ar_ambig_summarize = re.compile(
            ar_pref
            + r"(?:لخص|أوجز|تلخيص)\s+(?:لي\s+)?(?:الإيميلات|الايميلات|الرسائل|إيميلات|ايميلات|رسائل)"
            + end_punct,
            re.IGNORECASE,
        )
        self.ar_ambig_read = re.compile(
            ar_pref
            + r"(?:اقرأ|اقرا|اعرض|أرني|ارني|شوف|شيك\s+على)\s+(?:الإيميلات|الايميلات|الرسائل|البريد)"
            + end_punct,
            re.IGNORECASE,
        )
        self.ar_ambig_search = re.compile(
            ar_pref
            + r"(?:ابحث|دور|فتش)\s+(?:عن|في)\s+(?:إيميلات|ايميلات|رسائل|الإيميلات|الايميلات|الرسائل|البريد)"
            + end_punct,
            re.IGNORECASE,
        )
        self.ar_ambig_show = re.compile(
            ar_pref
            + r"(?:اعرض|اقرأ|اقرا|أرني|ارني|افتح|شوف)\s+(?:الإيميل|الايميل|الرسالة)"
            + end_punct,
            re.IGNORECASE,
        )

    def _normalize_text(self, text: str) -> str:
        """Apply Unicode NFKC normalization, strip format characters, and convert Eastern digits."""
        # 1. NFKC compatibility normalization
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Filter out non-essential control/format characters (Cf category) except standard spaces
        filtered = "".join(
            ch
            for ch in normalized
            if unicodedata.category(ch) != "Cf" or ch in ("\n", "\t", " ")
        )

        # 3. Translate Eastern Arabic digits (٠-٩) to ASCII (0-9)
        with_ascii_digits = filtered.translate(EASTERN_DIGITS_TRANS)

        # 4. Collapse consecutive whitespace
        return " ".join(with_ascii_digits.strip().split())

    def _strip_arabic_diacritics(self, text: str) -> str:
        """Strip Arabic tashkeel (diacritics) and tatweel for matching."""
        without_tashkeel = TASHKEEL_REGEX.sub("", text)
        return TATWEEL_REGEX.sub("", without_tashkeel)

    def _detect_languages(
        self, raw_text: str, explicit_lang_str: str | None = None
    ) -> tuple[str, str]:
        """Detect base input language and requested response language.

        Returns:
            Tuple of (input_language, response_language).
        """
        arabic_chars = len(re.findall(r"[\u0600-\u06FF]", raw_text))
        latin_chars = len(re.findall(r"[a-zA-Z]", raw_text))
        input_lang = "ar" if arabic_chars > latin_chars else "en"

        if explicit_lang_str:
            clean_explicit = explicit_lang_str.strip().lower()
            if any(
                w in clean_explicit
                for w in ("arabic", "ar", "عربي", "العربية", "بالعربي")
            ):
                return input_lang, "ar"
            if any(
                w in clean_explicit
                for w in (
                    "english",
                    "en",
                    "انجليزي",
                    "الانجليزية",
                    "إنجليزي",
                    "الإنجليزية",
                )
            ):
                return input_lang, "en"

        # Check for explicit language requests in the text
        if re.search(
            r"\b(?:in\s+arabic)\b|(?:بالعربي|باللغة\s+العربية)",
            raw_text,
            re.IGNORECASE,
        ):
            return input_lang, "ar"
        if re.search(
            r"\b(?:in\s+english)\b|(?:بالانجليزي|باللغة\s+الانجليزية|بالإنجليزي|باللغة\s+الإنجليزية)",
            raw_text,
            re.IGNORECASE,
        ):
            return input_lang, "en"

        return input_lang, input_lang

    def _validate_count(self, count_str: str) -> int:
        """Validate and bound requested count."""
        try:
            count = int(count_str)
        except ValueError as err:
            raise IntentParsingError(f"Invalid count format: '{count_str}'") from err

        if count < MIN_ALLOWED_COUNT:
            raise InvalidCountError(
                count=count,
                max_allowed=MAX_ALLOWED_COUNT,
                message=f"Requested count ({count}) must be greater than or equal to {MIN_ALLOWED_COUNT}.",
            )
        if count > MAX_ALLOWED_COUNT:
            raise InvalidCountError(
                count=count,
                max_allowed=MAX_ALLOWED_COUNT,
                message=f"Requested count ({count}) exceeds maximum allowed limit of {MAX_ALLOWED_COUNT}.",
            )
        return count

    def _validate_email_id(self, id_str: str) -> int:
        """Validate email ID."""
        try:
            email_id = int(id_str)
        except ValueError as err:
            raise IntentParsingError(f"Invalid email ID format: '{id_str}'") from err

        if email_id < 1:
            raise IntentParsingError(
                f"Requested email ID ({email_id}) must be a positive integer."
            )
        return email_id

    def parse(
        self,
        prompt: str,
        raise_on_ambiguity: bool = False,
    ) -> TaskIntent:
        """Deterministically parse a user prompt into a structured TaskIntent.

        Args:
            prompt: User natural language request.
            raise_on_ambiguity: If True, raises AmbiguousIntentError for ambiguous inputs
                instead of returning a TaskIntent with requires_clarification=True.

        Returns:
            TaskIntent model with resolved intent, resource, action, and bounds.

        Raises:
            EmptyRequestError: If prompt is empty or whitespace only.
            IntentParsingError: If prompt exceeds maximum length or syntax is malformed.
            UnsupportedIntentError: If prompt requests an unsupported action (delete, send, etc.)
                or contains prompt injection override patterns.
            InvalidCountError: If requested item count is <= 0 or > 20.
            AmbiguousIntentError: If prompt is compound or ambiguous and raise_on_ambiguity is True.
        """
        # 1. Input sanitization and length check
        if not prompt or not prompt.strip():
            raise EmptyRequestError("User request cannot be empty or whitespace only.")

        clean_prompt = prompt.strip()
        if len(clean_prompt) > MAX_REQUEST_LENGTH:
            raise IntentParsingError(
                f"User request exceeds maximum length of {MAX_REQUEST_LENGTH} characters."
            )

        # 2. Normalize Unicode and digits
        normalized = self._normalize_text(clean_prompt)
        text_no_diacritics = self._strip_arabic_diacritics(normalized)

        # 3. Check for prompt injection override markers
        for pattern in INJECTION_OVERRIDE_PATTERNS:
            if pattern.search(text_no_diacritics):
                raise UnsupportedIntentError(
                    action="adversarial_override",
                    message="Adversarial instructions or prompt injection override attempt detected in request.",
                )

        # 4. Check for compound actions (e.g. read AND delete, summarize AND search)
        for pattern in COMPOUND_ACTION_PATTERNS:
            if pattern.search(text_no_diacritics):
                msg = (
                    "Compound requests combining multiple actions are not supported "
                    "in a single task intent. Please submit separate single-action requests."
                )
                if raise_on_ambiguity:
                    raise AmbiguousIntentError(
                        message=msg,
                        clarification_prompt=msg,
                        reason="COMPOUND_REQUEST",
                    )
                return TaskIntent(
                    intent_type=IntentType.AMBIGUOUS,
                    resource_type=ResourceType.UNKNOWN,
                    requested_action=ActionType.UNKNOWN,
                    confidence=0.0,
                    is_ambiguous=True,
                    requires_clarification=True,
                    clarification_prompt=msg,
                    source_request=clean_prompt,
                )

        # 5. Check for unsupported/forbidden operations (e.g. send, delete, modify)
        # Note: If it's a search for a keyword, search pattern takes precedence if strictly formulated,
        # but if the prompt is an imperative delete/send/modify, reject immediately.
        for action_name, pattern in UNSUPPORTED_ACTIONS:
            if pattern.search(text_no_diacritics):
                # Verify if this is an explicit search query containing the word
                is_search = bool(
                    self.en_search.match(text_no_diacritics)
                    or self.ar_search.match(text_no_diacritics)
                )
                if not is_search:
                    raise UnsupportedIntentError(
                        action=action_name,
                        message=f"Action '{action_name}' is not supported. AEGIS-CORE is strictly read-only.",
                    )

        # 6. Detect language preference
        input_lang, resp_lang = self._detect_languages(clean_prompt)

        # 7. Pattern Matching for Supported Intents

        # --- A. SUMMARIZE RECENT EMAILS ---
        m = self.en_summarize.match(text_no_diacritics) or self.en_summarize_alt.match(
            text_no_diacritics
        )
        if m:
            count = self._validate_count(m.group(1))
            explicit_lang = m.group(2) if len(m.groups()) >= 2 else None
            _, final_lang = self._detect_languages(clean_prompt, explicit_lang)
            return TaskIntent(
                intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SUMMARIZE,
                requested_count=count,
                response_language=final_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        m = self.ar_summarize.match(text_no_diacritics)
        if m:
            count = self._validate_count(m.group(1))
            explicit_lang = m.group(2) if len(m.groups()) >= 2 else None
            _, final_lang = self._detect_languages(clean_prompt, explicit_lang)
            return TaskIntent(
                intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SUMMARIZE,
                requested_count=count,
                response_language=final_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        # --- B. READ LATEST EMAILS ---
        m = (
            self.en_read_latest.match(text_no_diacritics)
            or self.en_read_latest_alt.match(text_no_diacritics)
            or self.en_read_inbox_count.match(text_no_diacritics)
        )
        if m:
            count = self._validate_count(m.group(1))
            return TaskIntent(
                intent_type=IntentType.READ_LATEST_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.READ,
                requested_count=count,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        m = self.ar_read_latest.match(text_no_diacritics)
        if m:
            count = self._validate_count(m.group(1))
            return TaskIntent(
                intent_type=IntentType.READ_LATEST_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.READ,
                requested_count=count,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        # --- C. SEARCH EMAILS ---
        m = self.en_search.match(text_no_diacritics) or self.en_search_in.match(
            text_no_diacritics
        )
        if m:
            raw_query = m.group(1).strip().strip("'\"").strip()
            if not raw_query:
                msg = "Please specify an explicit search query or keyword (e.g. 'Search emails for assignment')."
                if raise_on_ambiguity:
                    raise AmbiguousIntentError(msg, clarification_prompt=msg)
                return TaskIntent(
                    intent_type=IntentType.AMBIGUOUS,
                    resource_type=ResourceType.EMAIL,
                    requested_action=ActionType.SEARCH,
                    confidence=0.0,
                    is_ambiguous=True,
                    requires_clarification=True,
                    clarification_prompt=msg,
                    source_request=clean_prompt,
                )
            if len(raw_query) > MAX_QUERY_LENGTH:
                raise IntentParsingError(
                    f"Search query exceeds maximum length of {MAX_QUERY_LENGTH} characters."
                )
            return TaskIntent(
                intent_type=IntentType.SEARCH_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SEARCH,
                search_query=raw_query,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        m = self.ar_search.match(text_no_diacritics) or self.ar_search_in.match(
            text_no_diacritics
        )
        if m:
            raw_query = m.group(1).strip().strip("'\"").strip()
            if not raw_query:
                msg = (
                    "يرجى تحديد كلمة البحث (مثال: 'ابحث عن إيميلات فيها كلمة امتحان')."
                )
                if raise_on_ambiguity:
                    raise AmbiguousIntentError(msg, clarification_prompt=msg)
                return TaskIntent(
                    intent_type=IntentType.AMBIGUOUS,
                    resource_type=ResourceType.EMAIL,
                    requested_action=ActionType.SEARCH,
                    confidence=0.0,
                    is_ambiguous=True,
                    requires_clarification=True,
                    clarification_prompt=msg,
                    source_request=clean_prompt,
                )
            if len(raw_query) > MAX_QUERY_LENGTH:
                raise IntentParsingError(
                    f"Search query exceeds maximum length of {MAX_QUERY_LENGTH} characters."
                )
            return TaskIntent(
                intent_type=IntentType.SEARCH_EMAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SEARCH,
                search_query=raw_query,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        # --- D. READ EMAIL DETAILS BY ID ---
        m = self.en_show_email.match(text_no_diacritics) or self.en_email_direct.match(
            text_no_diacritics
        )
        if m:
            email_id = self._validate_email_id(m.group(1))
            return TaskIntent(
                intent_type=IntentType.READ_EMAIL_DETAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SHOW,
                requested_email_id=email_id,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        m = self.ar_show_email.match(text_no_diacritics) or self.ar_email_direct.match(
            text_no_diacritics
        )
        if m:
            email_id = self._validate_email_id(m.group(1))
            return TaskIntent(
                intent_type=IntentType.READ_EMAIL_DETAILS,
                resource_type=ResourceType.EMAIL,
                requested_action=ActionType.SHOW,
                requested_email_id=email_id,
                response_language=resp_lang,
                confidence=1.0,
                source_request=clean_prompt,
            )

        # 8. Ambiguous patterns requiring explicit clarification
        clarification_msg: str | None = None

        if self.en_ambig_summarize.match(text_no_diacritics):
            clarification_msg = "Please specify how many recent emails to summarize (e.g. 'Summarize my latest 3 emails')."
        elif self.ar_ambig_summarize.match(text_no_diacritics):
            clarification_msg = "يرجى تحديد عدد الإيميلات المطلوب تلخيصها (مثال: 'لخص آخر 3 إيميلات بالعربي')."
        elif self.en_ambig_read.match(text_no_diacritics):
            clarification_msg = "Please specify how many recent emails to read (e.g. 'Read my latest 3 emails')."
        elif self.ar_ambig_read.match(text_no_diacritics):
            clarification_msg = (
                "يرجى تحديد عدد الإيميلات المطلوب قراءتها (مثال: 'اقرأ آخر 3 إيميلات')."
            )
        elif self.en_ambig_search.match(text_no_diacritics):
            clarification_msg = "Please specify an explicit search query (e.g. 'Search emails for assignment')."
        elif self.ar_ambig_search.match(text_no_diacritics):
            clarification_msg = (
                "يرجى تحديد كلمة البحث (مثال: 'ابحث عن إيميلات فيها كلمة امتحان')."
            )
        elif self.en_ambig_show.match(text_no_diacritics):
            clarification_msg = (
                "Please specify the email ID to view (e.g. 'Show email 7')."
            )
        elif self.ar_ambig_show.match(text_no_diacritics):
            clarification_msg = (
                "يرجى تحديد رقم الإيميل المطلوب عرضه (مثال: 'اعرض الإيميل رقم 7')."
            )
        else:
            # Conservative general fallback: Do not guess or inflate permissions!
            if input_lang == "ar":
                clarification_msg = (
                    "يرجى توضيح طلبك: يدعم النظام قراءة أحدث الإيميلات (مثال: 'اقرأ آخر 3 إيميلات')، "
                    "تلخيص الإيميلات، البحث بكلمة مفتاحية، أو عرض إيميل محدد برقم."
                )
            else:
                clarification_msg = (
                    "Please clarify your request: AEGIS-CORE supports reading latest emails "
                    "(e.g. 'Read my latest 3 emails'), summarizing recent emails, searching by keyword, "
                    "or viewing an email by ID."
                )

        if raise_on_ambiguity:
            raise AmbiguousIntentError(
                message=clarification_msg,
                clarification_prompt=clarification_msg,
                reason="AMBIGUOUS_REQUEST",
            )

        return TaskIntent(
            intent_type=IntentType.AMBIGUOUS,
            resource_type=ResourceType.EMAIL
            if input_lang == "en"
            else ResourceType.UNKNOWN,
            requested_action=ActionType.UNKNOWN,
            confidence=0.0,
            is_ambiguous=True,
            requires_clarification=True,
            clarification_prompt=clarification_msg,
            response_language=resp_lang,
            source_request=clean_prompt,
        )

    def parse_or_raise(self, prompt: str) -> TaskIntent:
        """Parse intent and strictly raise AmbiguousIntentError if ambiguous."""
        return self.parse(prompt, raise_on_ambiguity=True)


# Default singleton instance
default_intent_parser = DeterministicIntentParser()


def parse_intent(prompt: str, raise_on_ambiguity: bool = False) -> TaskIntent:
    """Module-level convenience function for deterministic intent parsing."""
    return default_intent_parser.parse(prompt, raise_on_ambiguity=raise_on_ambiguity)
