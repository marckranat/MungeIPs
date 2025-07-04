#!/bin/bash

# Exit on any error
set -e

# Input and output files
INPUT_FILE="ips.txt"
OUTPUT_FILE="processed_ips.txt"
TEMP_FILE="temp_ips.txt"
TEMP_IP_LIST="temp_ip_list.txt"
TEMP_24_COUNT="temp_24_count.txt"
TEMP_16_LIST="temp_16_list.txt"
TEMP_16_COUNT="temp_16_count.txt"

# Cleanup function
cleanup() {
    rm -f "$TEMP_FILE" "$TEMP_IP_LIST" "$TEMP_IP_LIST.new" "$TEMP_24_COUNT" "$TEMP_16_COUNT" "$TEMP_16_LIST"
}

# Set up cleanup trap
trap cleanup EXIT

# Function to validate IP address
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS=.
        read -r a b c d <<< "$ip"
        [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]
    else
        return 1
    fi
}

# Function to validate subnet
is_valid_subnet() {
    local subnet=$1
    [[ $subnet =~ ^[0-9]+$ ]] && [ "$subnet" -ge 0 ] && [ "$subnet" -le 32 ]
}

# Function to convert IP to integer for comparison
ip_to_int() {
    local ip=$1
    if ! is_valid_ip "$ip"; then
        echo "Error: Invalid IP address: $ip" >&2
        return 1
    fi
    local IFS=.
    read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Function to convert integer back to IP
int_to_ip() {
    local int=$1
    echo "$((int >> 24)).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$((int & 255 ))"
}

# Function to get /24 network address
get_network_24() {
    local ip=$1
    if ! is_valid_ip "$ip"; then
        echo "Error: Invalid IP address: $ip" >&2
        return 1
    fi
    local IFS=.
    read -r a b c d <<< "$ip"
    echo "$a.$b.$c.0/24"
}

# Function to get /16 network address
get_network_16() {
    local ip=$1
    if ! is_valid_ip "$ip"; then
        echo "Error: Invalid IP address: $ip" >&2
        return 1
    fi
    local IFS=.
    read -r a b c d <<< "$ip"
    echo "$a.$b.0.0/16"
}

# Function to expand a subnet into individual IPs or /16 networks
expand_subnet() {
    local ip=$1
    local cidr=$2
    
    if ! is_valid_ip "$ip"; then
        echo "Error: Invalid IP address: $ip" >&2
        return 1
    fi
    
    if ! is_valid_subnet "$cidr"; then
        echo "Error: Invalid subnet: $cidr" >&2
        return 1
    fi
    
    local start=$(ip_to_int "$ip")
    local num_ips=$((1 << (32 - cidr)))

    if [ "$cidr" -lt 16 ]; then
        # Break into /16 networks
        local num_networks=$((num_ips / 65536)) # 2^(32-16) = 65536 IPs per /16
        local base_ip=$start
        
        # Align to /16 boundary
        base_ip=$((base_ip & 0xFFFF0000))
        
        for ((i=0; i<num_networks; i++)); do
            local network_ip=$(int_to_ip $base_ip)
            echo "$(get_network_16 "$network_ip")"
            base_ip=$((base_ip + 65536))
        done
    elif [ "$cidr" -gt 24 ]; then
        # Expand to individual IPs
        for ((i=0; i<num_ips; i++)); do
            int_to_ip $((start + i))
        done
    else
        # Pass through /16 or /24
        echo "$ip/$cidr"
    fi
}

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found" >&2
    echo "Please create '$INPUT_FILE' with one IP address or subnet per line" >&2
    exit 1
fi

# Check if input file is readable
if [ ! -r "$INPUT_FILE" ]; then
    echo "Error: Cannot read input file '$INPUT_FILE'" >&2
    exit 1
fi

# Check if we can write to output location
if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    echo "Error: Cannot write to output file '$OUTPUT_FILE'" >&2
    exit 1
fi

echo "Processing IP addresses from '$INPUT_FILE'..."

# Step 1: Clean input and remove /32 (handle Windows line endings)
if ! sed 's/\/32\r\?$//' "$INPUT_FILE" > "$TEMP_FILE"; then
    echo "Error: Failed to process input file" >&2
    exit 1
fi

# Step 2: Process subnets
> "$TEMP_IP_LIST"
> "$TEMP_16_LIST"
line_num=0
while IFS=/ read -r ip subnet; do
    line_num=$((line_num + 1))
    
    # Skip empty lines and comments
    [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
    
    # Trim whitespace and carriage returns (handle Windows line endings)
    ip=$(echo "$ip" | tr -d '\r' | xargs)
    subnet=$(echo "$subnet" | tr -d '\r' | xargs)
    
    # Validate IP
    if ! is_valid_ip "$ip"; then
        echo "Warning: Invalid IP address '$ip' on line $line_num, skipping" >&2
        continue
    fi
    
    if [ -z "$subnet" ]; then
        # Single IP
        echo "$ip" >> "$TEMP_IP_LIST"
    else
        # Validate subnet
        if ! is_valid_subnet "$subnet"; then
            echo "Warning: Invalid subnet '/$subnet' for IP '$ip' on line $line_num, skipping" >&2
            continue
        fi
        
        # Block dangerous large subnets
        if [ "$subnet" -le 8 ]; then
            echo "Warning: Subnet '$ip/$subnet' too large (would generate millions of IPs), skipping" >&2
            continue
        fi
        
        # Use numeric comparison with proper validation
        if [ "$subnet" -eq 16 ]; then
            # Pass through /16
            echo "$ip/$subnet" >> "$TEMP_16_LIST"
        elif [ "$subnet" -eq 24 ]; then
            # Pass through /24
            echo "$ip/$subnet" >> "$TEMP_IP_LIST"
        elif [ "$subnet" -ge 18 ] && [ "$subnet" -le 23 ]; then
            # Convert /18 to /23 to /16
            echo "$(get_network_16 "$ip")" >> "$TEMP_16_LIST"
        else
            # Expand other subnets (smaller than /24 or larger than /16)
            if ! expand_subnet "$ip" "$subnet" >> "$TEMP_IP_LIST"; then
                echo "Warning: Failed to expand subnet '$ip/$subnet' on line $line_num, skipping" >&2
            fi
        fi
    fi
done < "$TEMP_FILE"

# Step 3: Group IPs by /24 and count occurrences
> "$TEMP_24_COUNT"
while IFS=/ read -r ip subnet; do
    # Skip empty lines
    [ -z "$ip" ] && continue
    
    if [ -z "$subnet" ]; then
        # Single IP, get its /24 network
        network=$(get_network_24 "$ip")
        echo "$network $ip" >> "$TEMP_24_COUNT"
    elif [ "$subnet" = "24" ]; then
        # Pass through /24
        echo "$ip/$subnet" >> "$TEMP_24_COUNT"
    fi
done < "$TEMP_IP_LIST"

# Step 4: Process /24 consolidation
> "$TEMP_IP_LIST.new"
awk -v temp_file="$TEMP_IP_LIST.new" '
    # Store IPs and count per /24
    /\/24$/ {
        print $0 >> temp_file
        next
    }
    {
        network=$1
        ip=$2
        networks[network]++
        ips[network] = (ips[network] ? ips[network] " " : "") ip
    }
    END {
        for (network in networks) {
            if (networks[network] >= 4) {
                print network >> temp_file
            } else {
                split(ips[network], ip_list, " ")
                for (i in ip_list) {
                    print ip_list[i] >> temp_file
                }
            }
        }
    }
' "$TEMP_24_COUNT"

# Step 5: Group /24s by /16 and consolidate if >= 4 /24s
> "$TEMP_16_COUNT"
while IFS=/ read -r ip subnet; do
    # Skip empty lines
    [ -z "$ip" ] && continue
    
    if [ "$subnet" = "24" ]; then
        network=$(get_network_16 "$ip")
        echo "$network $ip/$subnet" >> "$TEMP_16_COUNT"
    else
        # Pass through single IPs
        echo "$ip" >> "$TEMP_16_COUNT"
    fi
done < "$TEMP_IP_LIST.new"

# Step 6: Final output
> "$OUTPUT_FILE"
awk -v output_file="$OUTPUT_FILE" '
    /\/16$/ {
        networks[$1]++
        next
    }
    /\/24$/ {
        network=$1
        ip=$2
        networks[network]++
        subnets[network] = (subnets[network] ? subnets[network] " " : "") ip
    }
    !/\/[0-9]+$/ {
        print $0 >> output_file
    }
    END {
        for (network in networks) {
            if (networks[network] >= 4) {
                print network >> output_file
            } else {
                split(subnets[network], subnet_list, " ")
                for (i in subnet_list) {
                    print subnet_list[i] >> output_file
                }
            }
        }
    }
' "$TEMP_16_COUNT"

# Step 7: Append /16 networks from initial processing
cat "$TEMP_16_LIST" >> "$OUTPUT_FILE"

# Step 8: Clean up and sort
if ! sort -u "$OUTPUT_FILE" -o "$OUTPUT_FILE"; then
    echo "Error: Failed to sort output file" >&2
    exit 1
fi

echo "Successfully processed IP list and saved to '$OUTPUT_FILE'"

# Show summary
total_lines=$(wc -l < "$OUTPUT_FILE")
echo "Total entries in output: $total_lines"