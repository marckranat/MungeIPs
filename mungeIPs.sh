#!/bin/bash

# Input and output files
INPUT_FILE="ips.txt"
OUTPUT_FILE="processed_ips.txt"
TEMP_FILE="temp_ips.txt"
TEMP_IP_LIST="temp_ip_list.txt"
TEMP_24_COUNT="temp_24_count.txt"
TEMP_16_LIST="temp_16_list.txt"
TEMP_16_COUNT="temp_16_count.txt"

# Function to convert IP to integer for comparison
ip_to_int() {
    local IFS=.
    read -r a b c d <<< "$1"
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
    local IFS=.
    read -r a b c d <<< "$ip"
    echo "$a.$b.$c.0/24"
}

# Function to get /16 network address
get_network_16() {
    local ip=$1
    local IFS=.
    read -r a b c d <<< "$ip"
    echo "$a.$b.0.0/16"
}

# Function to expand a subnet into individual IPs or /16 networks
expand_subnet() {
    local ip=$1
    local cidr=$2
    local start=$(ip_to_int "$ip")
    local num_ips=$((1 << (32 - cidr)))

    if [ "$cidr" -lt 16 ]; then
        # Break into /16 networks
        local num_networks=$((num_ips / 65536)) # 2^(32-16) = 65536 IPs per /16
        local base_ip=$start
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

# Step 1: Clean input and remove /32
sed 's/\/32$//' "$INPUT_FILE" > "$TEMP_FILE"

# Step 2: Process subnets
> "$TEMP_IP_LIST"
> "$TEMP_16_LIST"
while IFS=/ read -r ip subnet; do
    # Skip empty lines
    [ -z "$ip" ] && continue
    
    if [ -z "$subnet" ]; then
        # Single IP
        echo "$ip" >> "$TEMP_IP_LIST"
    elif [ "$subnet" -eq 16 ]; then
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
        expand_subnet "$ip" "$subnet" >> "$TEMP_IP_LIST"
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
    elif [ "$subnet" == "24" ]; then
        # Pass through /24
        echo "$ip/$subnet" >> "$TEMP_24_COUNT"
    fi
done < "$TEMP_IP_LIST"

# Step 4: Process /24 consolidation
> "$TEMP_IP_LIST".new
awk '
    # Store IPs and count per /24
    /\/24$/ {
        print $0 >> "'"$TEMP_IP_LIST.new"'"
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
                print network >> "'"$TEMP_IP_LIST.new"'"
            } else {
                split(ips[network], ip_list, " ")
                for (i in ip_list) {
                    print ip_list[i] >> "'"$TEMP_IP_LIST.new"'"
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
    
    if [ "$subnet" == "24" ]; then
        network=$(get_network_16 "$ip")
        echo "$network $ip/$subnet" >> "$TEMP_16_COUNT"
    else
        # Pass through single IPs
        echo "$ip" >> "$TEMP_16_COUNT"
    fi
done < "$TEMP_IP_LIST.new"

# Step 6: Final output
> "$OUTPUT_FILE"
awk '
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
        print $0 >> "'"$OUTPUT_FILE"'"
    }
    END {
        for (network in networks) {
            if (networks[network] >= 4) {
                print network >> "'"$OUTPUT_FILE"'"
            } else {
                split(subnets[network], subnet_list, " ")
                for (i in subnet_list) {
                    print subnet_list[i] >> "'"$OUTPUT_FILE"'"
                }
            }
        }
    }
' "$TEMP_16_COUNT"

# Step 7: Append /16 networks from initial processing
cat "$TEMP_16_LIST" >> "$OUTPUT_FILE"

# Step 8: Clean up and sort
sort -u "$OUTPUT_FILE" -o "$OUTPUT_FILE"
rm -f "$TEMP_FILE" "$TEMP_IP_LIST" "$TEMP_IP_LIST.new" "$TEMP_24_COUNT" "$TEMP_16_COUNT" "$TEMP_16_LIST"

echo "Processed IP list saved to $OUTPUT_FILE"