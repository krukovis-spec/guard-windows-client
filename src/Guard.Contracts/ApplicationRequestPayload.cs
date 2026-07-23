using System;
using System.Globalization;

namespace Guard.Contracts
{
    public static class ApplicationRequestPayloadLimits
    {
        public const int MaximumPayloadBytes = 1024;
        public const int MaximumShortReasonCharacters = 160;
        public const int MaximumShortReasonUtf8Bytes =
            MaximumShortReasonCharacters * 4;
    }

    public sealed class CreateApplicationRequestPayload
    {
        public CreateApplicationRequestPayload(
            string observationId,
            string? shortReason)
        {
            if (!GuardIdentifier.IsCanonicalToken(observationId))
            {
                throw new ArgumentException(
                    "A bounded opaque observation identifier is required.",
                    nameof(observationId));
            }

            if (shortReason != null)
            {
                if (string.IsNullOrWhiteSpace(shortReason) ||
                    shortReason.Length >
                        ApplicationRequestPayloadLimits
                            .MaximumShortReasonCharacters ||
                    !string.Equals(
                        shortReason,
                        shortReason.Trim(),
                        StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        "The optional short reason is invalid.",
                        nameof(shortReason));
                }

                ValidateReasonCharacters(shortReason);
            }

            ObservationId = observationId;
            ShortReason = shortReason;
        }

        public string ObservationId { get; }

        public string? ShortReason { get; }

        private static void ValidateReasonCharacters(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                var category =
                    CharUnicodeInfo.GetUnicodeCategory(value, index);
                if (category == UnicodeCategory.Control ||
                    category == UnicodeCategory.Format ||
                    category == UnicodeCategory.LineSeparator ||
                    category == UnicodeCategory.ParagraphSeparator)
                {
                    throw new ArgumentException(
                        "The optional short reason cannot contain control or formatting characters.",
                        nameof(value));
                }

                if (char.IsHighSurrogate(character))
                {
                    if (index + 1 >= value.Length ||
                        !char.IsLowSurrogate(value[index + 1]))
                    {
                        throw new ArgumentException(
                            "The optional short reason must contain valid Unicode.",
                            nameof(value));
                    }

                    index++;
                }
                else if (char.IsLowSurrogate(character))
                {
                    throw new ArgumentException(
                        "The optional short reason must contain valid Unicode.",
                        nameof(value));
                }
            }
        }
    }
}
