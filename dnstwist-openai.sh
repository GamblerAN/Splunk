#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

DIR="/opt/dnstwist"
cd "$DIR"

# === FILE NAMES ===
RAW_JSON="twist_raw.temp"              # Intermediate file for raw dnstwist output
ENRICHED_JSON="twist_enriched.temp"    # Intermediate file after HTTP enrichment
FINAL_TEMP_JSON="twist_final.temp"     # Final analysis temporary file
FINAL_OUTPUT="twist.json"              # Final output file

OPENAI_API_KEY="${OPENAI_API_KEY}"
ORIGINAL_DOMAIN="test.com"              # Domain to compare all candidates against
EXCLUDED_DOMAINS=("test2.com" "known.example") # Add known domains you want to skip

# === FUNCTIONS ===

# Fetch raw HTML content with browser-like headers to bypass basic bot protection
fetch_text_raw() {
    local url="$1"
    curl -sL --insecure \
      -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36" \
      -e "https://google.com" \
      -H "Accept-Language: en-US,en;q=0.9" \
      -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
      --compressed \
      --cookie-jar /tmp/cookies.txt \
      --cookie /tmp/cookies.txt \
      --max-time 15 \
      --max-redirs 5 \
      "https://$url"
}

# Convert raw HTML to plain text using html2text
fetch_text() {
    fetch_text_raw "$1" | html2text -width 120
}

# Detect bot protection indicators in raw HTML
is_blocked_page() {
    local html="$1"
    echo "$html" | grep -iqE \
        'enable javascript|checking your browser|cf-browser-verification|Attention Required'
}

# Check if domain is in excluded list
is_excluded_domain() {
    local domain_to_check="$1"
    for excluded in "${EXCLUDED_DOMAINS[@]}"; do
        if [[ "$domain_to_check" == "$excluded" ]]; then
            return 0
        fi
    done
    return 1
}

# === Step 1: Prepare TLD list ===
echo "[*] Downloading TLD list"
curl -s -O https://data.iana.org/TLD/tlds-alpha-by-domain.txt
tail -n +2 tlds-alpha-by-domain.txt | tr 'A-Z' 'a-z' > tlds.txt
rm -f tlds-alpha-by-domain.txt

# === Step 2: Run dnstwist ===
echo "[*] Running dnstwist"
rm -f "$RAW_JSON" "$FINAL_OUTPUT"
dnstwist -r -g -s -w -a -b -f json -o "$RAW_JSON" -t 100 -d wordlist.txt --tld tlds.txt "$ORIGINAL_DOMAIN"

# === Step 3: Enrich with HTTP info ===
echo "[*] Enriching with HTTP status and location"
echo "[" > "$ENRICHED_JSON"
FIRST=1

jq -c '.[]' "$RAW_JSON" | while read -r entry; do
    domain=$(echo "$entry" | jq -r '.domain')

    if is_excluded_domain "$domain"; then
        echo "[!] Skipping known domain: $domain"
        continue
    fi

    if ! getent hosts "$domain" > /dev/null; then
        echo "[!] Skipping unresolved domain: $domain"
        enriched=$(echo "$entry" | jq \
            --arg status "Unresolved DNS" \
            --arg location "" \
            '. + {
                http_status: $status,
                http_location: $location,
                skip_analysis: true
            }')
    else
        echo "  → $domain"
        CURL_OUTPUT=$(curl -sS -D - --insecure --max-time 5 "https://$domain" 2>&1) || true

        if echo "$CURL_OUTPUT" | grep -qiE 'could not resolve|connection refused|failed to connect|timed out|SSL certificate problem|maximum.*redirects|unrecognized name'; then
            echo "[!] Curl connection error: $domain"
            enriched=$(echo "$entry" | jq \
                --arg status "Connection Error" \
                --arg location "" \
                '. + {
                    http_status: $status,
                    http_location: $location,
                    skip_analysis: true
                }')
        else
            HEADER=$(echo "$CURL_OUTPUT" | awk 'NR==1,/^$/')
            HTTP_LINE=$(echo "$HEADER" | head -n 1 | tr -d '\r')
            LOCATION=$(echo "$HEADER" | grep -i '^Location:' | head -n 1 | sed 's/^[Ll]ocation:[[:space:]]*//;s/\r$//')

            enriched=$(echo "$entry" | jq \
                --arg status "$HTTP_LINE" \
                --arg location "$LOCATION" \
                '. + {
                    http_status: $status,
                    http_location: $location
                }')
        fi
    fi

    if [[ $FIRST -eq 1 ]]; then
        FIRST=0
    else
        echo "," >> "$ENRICHED_JSON"
    fi
    echo "$enriched" >> "$ENRICHED_JSON"
done

echo "]" >> "$ENRICHED_JSON"

# === Step 4: Fetch original site content ===
echo "[*] Fetching original site content"
ORIGINAL_TEXT=$(fetch_text "$ORIGINAL_DOMAIN")

# === Step 5: Analyze with OpenAI ===
echo "[*] Analyzing with OpenAI"
echo "[" > "$FINAL_TEMP_JSON"
FIRST=1

jq -c '.[] | select(type == "object" and has("domain") and (.skip_analysis != true))' "$ENRICHED_JSON" | while read -r item; do
    domain=$(echo "$item" | jq -r '.domain')
    echo "  → Analyzing: $domain"

    HTML_RAW=$(fetch_text_raw "$domain" 2>&1) || true

    if echo "$HTML_RAW" | grep -qi 'maximum.*redirects'; then
        echo "[!] Redirect loop detected: $domain"
        result=$(echo "$item" | jq --arg comment "Redirect loop (too many redirects)" \
            '. + {
                phishing_similarity: 0,
                phishing_verdict: "Redirect Loop",
                phishing_comment: $comment,
                phishing_blocked: true
            }')
    elif [[ -z "$HTML_RAW" ]]; then
        echo "[!] Empty response from $domain — skipping"
        result=$(echo "$item" | jq --arg comment "No response from host (timeout or empty body)" \
            '. + {
                phishing_similarity: 0,
                phishing_verdict: "Unreachable",
                phishing_comment: $comment,
                phishing_blocked: true
            }')
    else
        TEXT_CLEAN=$(echo "$HTML_RAW" | html2text -width 120)

        # Additional check for completely empty html2text output (e.g. <script redirects>)
        if [[ -z "${TEXT_CLEAN// /}" ]]; then
            echo "[!] html2text returned empty output — skipping analysis"
            result=$(echo "$item" | jq --arg comment "html2text returned empty body — likely redirect-only or script-only page" \
                '. + {
                    phishing_similarity: 0,
                    phishing_verdict: "Empty after parsing",
                    phishing_comment: $comment,
                    phishing_blocked: true
                }')
        elif is_blocked_page "$HTML_RAW"; then
            echo "[!] Blocked by protection: $domain"
            result=$(echo "$item" | jq --arg comment "Blocked by bot protection (e.g. JS challenge or CAPTCHA)" \
                '. + {
                    phishing_similarity: 0,
                    phishing_verdict: "Blocked",
                    phishing_comment: $comment,
                    phishing_blocked: true
                }')
        else
            payload=$(jq -n --arg orig "${ORIGINAL_TEXT:0:3000}" --arg susp "${TEXT_CLEAN:0:3000}" ' {
                "model": "gpt-4o",
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": "You are an expert in detecting phishing websites."},
                    {"role": "user", "content": "Compare the following websites and estimate similarity (0-100%).\n\nOriginal:\n\($orig)\n\nSuspicious:\n\($susp)\n\nReply ONLY in strict JSON format. Do not explain. Respond like:\n{\"similarity\": 85, \"verdict\": \"Likely phishing\", \"comment\": \"...\"}"}
                ]
            }')

            RESPONSE=$(curl -s https://api.openai.com/v1/chat/completions \
                -H "Authorization: Bearer $OPENAI_API_KEY" \
                -H "Content-Type: application/json" \
                -d "$payload")

            RAW_RESULT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty' | sed -e '/^```/d')

            if [[ -n "$RAW_RESULT" ]] && echo "$RAW_RESULT" | jq empty 2>/dev/null; then
                similarity=$(echo "$RAW_RESULT" | jq -r '.similarity // 0')
                verdict=$(echo "$RAW_RESULT" | jq -r '.verdict // "Unknown"')
                comment=$(echo "$RAW_RESULT" | jq -r '.comment // ""')
            else
                similarity=0
                verdict="Parse error"
                comment="Response not valid JSON"
            fi

            result=$(echo "$item" | jq --argjson similarity "$similarity" \
                                       --arg verdict "$verdict" \
                                       --arg comment "$comment" \
                                       '. + {
                                           phishing_similarity: $similarity,
                                           phishing_verdict: $verdict,
                                           phishing_comment: $comment,
                                           phishing_blocked: false
                                       }')
        fi
    fi

    if [[ $FIRST -eq 1 ]]; then
        FIRST=0
    else
        echo "," >> "$FINAL_TEMP_JSON"
    fi

    echo "$result" >> "$FINAL_TEMP_JSON"
done

echo "]" >> "$FINAL_TEMP_JSON"

# === Step 6: Finalize ===
echo "[*] Finalizing output: $FINAL_OUTPUT"
mv "$FINAL_TEMP_JSON" "$FINAL_OUTPUT"
echo "✅ Done: $FINAL_OUTPUT"
