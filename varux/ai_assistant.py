"""OpenAI destekli güvenlik ve kod öneri asistanı servisi.

Bu katman, dashboard veya CLI üzerinden gelen talepleri tek bir
ara yüzden geçirerek OpenAI sohbet modellerini çağırır. Bağlam olarak
son keşif sonuçları, hedef bilgisi veya kullanıcı notları gibi
verileri alıp istemciye iletilmek üzere tek bir yanıt döndürür.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from openai import OpenAI, OpenAIError


@dataclass
class AIAssistant:
    """OpenAI sohbet modelleri için hafif bir istemci sarmalayıcı."""

    api_key: Optional[str] = None
    model: str = "gpt-4o-mini"
    system_prompt: str = (
        "Sen VARUX güvenlik ve kod asistanısın. Bulgu özetlerini, hedef "
        "bilgilerini ve kullanıcı isteklerini analiz ederek kısa, eyleme "
        "dönük ve teknik yanıtlar üret. Gerektiğinde örnek kod blokları ve "
        "adım adım ilerleyiş önerileri ver."
    )
    client: Optional[OpenAI] = field(init=False, default=None)

    def __post_init__(self) -> None:
        key = self.api_key or os.getenv("OPENAI_API_KEY")
        self.api_key = key
        if key:
            self.client = OpenAI(api_key=key)

        # Ortam değişkeni ile model override desteği
        env_model = os.getenv("VARUX_OPENAI_MODEL")
        if env_model:
            self.model = env_model

    def available(self) -> bool:
        """İstemcinin kullanılabilir olup olmadığını döndür."""

        return self.client is not None

    def _build_user_prompt(self, prompt: str, context: Optional[Dict[str, Any]]) -> str:
        """Bağlamı temizleyip tek bir kullanıcı mesajı halinde derle."""

        context_lines: List[str] = []
        if context:
            if context.get("target"):
                context_lines.append(f"Hedef: {context['target']}")
            if context.get("summary"):
                summary_parts = [
                    f"Toplam Cihaz: {context['summary'].get('total_devices', 0)}",
                    f"Kritik: {context['summary'].get('high_risk_devices', 0)}",
                ]
                context_lines.append("İstatistik: " + " | ".join(summary_parts))
            devices = context.get("devices") or []
            if devices:
                sample_devices = devices[:5]
                for device in sample_devices:
                    context_lines.append(
                        f"Cihaz {device.get('ip')}: {device.get('vendor', 'Bilinmiyor')} - "
                        f"Risk: {device.get('criticality', 'bilinmiyor')}"
                    )
            notes = context.get("notes")
            if notes:
                context_lines.append(f"Ek Notlar: {notes}")

        compiled_context = "\n".join(context_lines)
        if compiled_context:
            return f"{prompt}\n\nBağlam:\n{compiled_context}"
        return prompt

    def generate_assistance(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """OpenAI'den yanıt üretip sadeleştirilmiş sözlük döndür."""

        if not prompt:
            return {"error": "İstek içeriği boş olamaz."}

        if not self.available():
            return {"error": "OpenAI API anahtarı tanımlı değil."}

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": self._build_user_prompt(prompt, context)},
        ]

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=500,
            )
            content = response.choices[0].message.content
            return {
                "assistant_response": content,
                "model": self.model,
                "usage": response.usage.to_dict() if hasattr(response, "usage") else {},
            }
        except OpenAIError as exc:  # pragma: no cover - ağ/kimlik doğrulama hataları
            return {"error": f"OpenAI hatası: {exc}"}
        except Exception as exc:  # pragma: no cover - beklenmeyen hatalar
            return {"error": f"Beklenmeyen hata: {exc}"}


__all__ = ["AIAssistant"]
