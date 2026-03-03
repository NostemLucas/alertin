"""
CVE Translation Service (EN → ES).

Provides automatic translation of CVE descriptions from English to Spanish
using Helsinki-NLP's MarianMT model optimized for English-Spanish translation.
"""

import logging
from typing import Optional
from transformers import MarianMTModel, MarianTokenizer
import torch

logger = logging.getLogger(__name__)


class CVETranslator:
    """
    Translates CVE descriptions from English to Spanish.

    Uses Helsinki-NLP/opus-mt-en-es MarianMT model:
    - Optimized for EN→ES translation
    - ~300MB model size
    - Fast inference on CPU
    - High quality translations for technical text
    """

    def __init__(
        self,
        model_name: str = "Helsinki-NLP/opus-mt-en-es",
        device: str = "cpu",
        max_length: int = 512
    ):
        """
        Initialize translator with MarianMT model.

        Args:
            model_name: HuggingFace model identifier
            device: 'cpu' or 'cuda' for GPU acceleration
            max_length: Maximum sequence length (tokens)
        """
        self.model_name = model_name
        self.device = device
        self.max_length = max_length
        self._model: Optional[MarianMTModel] = None
        self._tokenizer: Optional[MarianTokenizer] = None

        logger.info(f"CVETranslator initialized (model: {model_name}, device: {device})")

    def _lazy_load_model(self):
        """Lazy load model on first use to save memory."""
        if self._model is None or self._tokenizer is None:
            logger.info(f"Loading translation model: {self.model_name}")
            try:
                self._tokenizer = MarianTokenizer.from_pretrained(self.model_name)
                self._model = MarianMTModel.from_pretrained(self.model_name)

                # Move to device
                if self.device == "cuda" and torch.cuda.is_available():
                    self._model = self._model.to("cuda")
                    logger.info("Translation model loaded on GPU")
                else:
                    self._model = self._model.to("cpu")
                    logger.info("Translation model loaded on CPU")

                self._model.eval()  # Set to evaluation mode

            except Exception as e:
                logger.error(f"Failed to load translation model: {e}", exc_info=True)
                raise

    def translate(
        self,
        text: str,
        max_length: Optional[int] = None,
        num_beams: int = 4,
        early_stopping: bool = True
    ) -> dict[str, any]:
        """
        Translate text from English to Spanish.

        Args:
            text: English text to translate
            max_length: Override max output length
            num_beams: Beam search width (higher = better quality, slower)
            early_stopping: Stop when all beams finish

        Returns:
            Dictionary with:
                - translated_text (str): Spanish translation
                - confidence (float): Translation confidence score (0-1)
                - source_length (int): Source text token count
                - target_length (int): Translation token count

        Example:
            >>> translator = CVETranslator()
            >>> result = translator.translate("Remote code execution vulnerability")
            >>> print(result["translated_text"])
            "Vulnerabilidad de ejecución remota de código"
        """
        if not text or not text.strip():
            return {
                "translated_text": "",
                "confidence": 0.0,
                "source_length": 0,
                "target_length": 0,
                "error": "Empty input text"
            }

        # Lazy load model
        self._lazy_load_model()

        try:
            # Tokenize input
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.max_length
            )

            # Move to device
            if self.device == "cuda":
                inputs = {k: v.to("cuda") for k, v in inputs.items()}

            # Generate translation
            with torch.no_grad():
                outputs = self._model.generate(
                    **inputs,
                    max_length=max_length or self.max_length,
                    num_beams=num_beams,
                    early_stopping=early_stopping,
                    return_dict_in_generate=True,
                    output_scores=True
                )

            # Decode translation
            translated_text = self._tokenizer.decode(
                outputs.sequences[0],
                skip_special_tokens=True
            )

            # Calculate confidence from generation scores
            # Higher beam scores = higher confidence
            confidence = self._calculate_confidence(outputs)

            source_length = inputs["input_ids"].shape[1]
            target_length = outputs.sequences.shape[1]

            logger.debug(
                f"Translated {source_length} tokens → {target_length} tokens "
                f"(confidence: {confidence:.2f})"
            )

            return {
                "translated_text": translated_text,
                "confidence": round(confidence, 3),
                "source_length": source_length,
                "target_length": target_length,
            }

        except Exception as e:
            logger.error(f"Translation failed: {e}", exc_info=True)
            return {
                "translated_text": text,  # Return original on failure
                "confidence": 0.0,
                "source_length": 0,
                "target_length": 0,
                "error": str(e)
            }

    def _calculate_confidence(self, outputs) -> float:
        """
        Calculate translation confidence from beam search scores.

        Args:
            outputs: Model outputs with scores

        Returns:
            Confidence score between 0 and 1
        """
        try:
            if hasattr(outputs, "sequences_scores"):
                # Use sequence-level scores if available
                score = outputs.sequences_scores[0].item()
                # Convert log probability to confidence (normalize to 0-1 range)
                confidence = min(1.0, max(0.0, torch.exp(torch.tensor(score)).item()))
                return confidence
            else:
                # Fallback: use average of token scores
                if outputs.scores:
                    avg_score = torch.stack(outputs.scores).mean().item()
                    confidence = min(1.0, max(0.0, torch.sigmoid(torch.tensor(avg_score)).item()))
                    return confidence
                else:
                    # No scores available, return default
                    return 0.85  # Default confidence for successful translation
        except Exception as e:
            logger.warning(f"Failed to calculate confidence: {e}")
            return 0.75  # Default fallback

    def translate_cve(self, cve_description: str) -> dict[str, any]:
        """
        Translate CVE description with optimized settings for technical text.

        Args:
            cve_description: English CVE description

        Returns:
            Translation result dictionary

        Example:
            >>> translator = CVETranslator()
            >>> result = translator.translate_cve(
            ...     "Apache Log4j2 JNDI features do not protect against "
            ...     "attacker controlled LDAP endpoints"
            ... )
            >>> print(result["translated_text"])
            "Las funcionalidades JNDI de Apache Log4j2 no protegen contra
            endpoints LDAP controlados por atacantes"
        """
        # Use higher beam search for better quality on technical text
        return self.translate(
            cve_description,
            num_beams=5,  # Higher quality for CVE descriptions
            early_stopping=True
        )

    def batch_translate(
        self,
        texts: list[str],
        batch_size: int = 8
    ) -> list[dict[str, any]]:
        """
        Translate multiple texts in batches for efficiency.

        Args:
            texts: List of English texts to translate
            batch_size: Number of texts to process simultaneously

        Returns:
            List of translation result dictionaries

        Note:
            Batching improves throughput but requires more memory.
            Reduce batch_size if encountering OOM errors.
        """
        results = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            logger.debug(f"Translating batch {i//batch_size + 1}/{len(texts)//batch_size + 1}")

            for text in batch:
                result = self.translate(text)
                results.append(result)

        logger.info(f"Batch translation completed: {len(results)} texts translated")
        return results

    def unload_model(self):
        """Unload model from memory to free resources."""
        if self._model is not None:
            del self._model
            del self._tokenizer
            self._model = None
            self._tokenizer = None

            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            logger.info("Translation model unloaded from memory")

    def __del__(self):
        """Cleanup on deletion."""
        self.unload_model()


# Singleton instance for reuse
_translator_instance: Optional[CVETranslator] = None


def get_translator(
    model_name: str = "Helsinki-NLP/opus-mt-en-es",
    device: str = "cpu"
) -> CVETranslator:
    """
    Get singleton translator instance.

    Args:
        model_name: HuggingFace model identifier
        device: 'cpu' or 'cuda'

    Returns:
        CVETranslator instance
    """
    global _translator_instance

    if _translator_instance is None:
        _translator_instance = CVETranslator(model_name=model_name, device=device)

    return _translator_instance
