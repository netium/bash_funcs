#! /usr/bin/bash

# This source code is under the GPL3.0 license

function cmd_exist() {
	local OPTIND

	if (( $# != 1)) ; then
		echo "No command has been provided."
		return 1
	fi 

	eval which $1 2>&1 > /dev/null

	return $?
}

# Function: cert_con_mqtt
# Description: Test connect to Azure IoT Hub MQTT by using the X509 cert based device
# Options:
#	-f: IoT Hub MQTT exposed FQDN via the Tiserv
#	-h: IoT Hub hostname
#	-c: Device certificate file (the certificate key shall include the device certificate chain)
#	-k: Device key file
# Return: 0 if success, non-0 otherwise
function cert_con_mqtt() {
	local OPTIND
	while getopts ":f:h:c:k:" opt; do
		case $opt in
			f ) local fqdn=$OPTARG ;;
			h ) local hostname=$OPTARG ;;
			k ) local key_file=$OPTARG ;;
			c ) local cert_file=$OPTARG ;;
			\? ) echo "Unknown options: $opt" ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))
	local ret

	if ! cmd_exist openssl ; then
		echo "Openssl cannot be found, please install it first before running this funciton"
		return 1
	fi 

	if ! cmd_exist mosquitto_pub ; then
		echo "mosquitto cannot be found, please install it first before running this funciton"
		return 1
	fi

	cn=$(openssl x509 -noout -subject -in "${cert_file}" | grep -Eo 'CN\s+=\s+.*$' | cut -d '=' -f 2 | xargs)
	ret=$?
	if ((ret != 0)) ; then 
		echo "Cannot get the common name from the cert"
		return 1
	fi

	mosquitto_pub -c -d -h $fqdn -p 8883 -i "$cn" -u "$hostname/$cn/?api-version=2021-04-12" -t "devices/$cn/messages/events/" --capath "/etc/ssl/certs/" -V mqttv311 -m '{"id":"123"}' -q 1 --cert "$cert_file" --key "$key_file" --tls-version tlsv1.2 --insecure
} 

# Function: cert_sub_mqtt
# Description: Test subscription to Azure IoT Hub MQTT by using the X509 cert based device
# Options:
#	-f: IoT Hub MQTT exposed FQDN via the Tiserv
#	-h: IoT Hub hostname
#	-c: Device certificate file (the certificate key shall include the device certificate chain)
#	-k: Device key file
# Return: 0 if success, non-0 otherwise
function cert_sub_mqtt() {
	local OPTIND
	while getopts ":f:h:c:k:" opt; do
		case $opt in
			f ) local fqdn=$OPTARG ;;
			h ) local hostname=$OPTARG ;;
			k ) local key_file=$OPTARG ;;
			c ) local cert_file=$OPTARG ;;
			\? ) echo "Unknown options: $opt" ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))
	local ret

	if ! cmd_exist openssl ; then
		echo "Openssl cannot be found, please install it first before running this funciton"
		return 1
	fi 

	if ! cmd_exist mosquitto_pub ; then
		echo "mosquitto cannot be found, please install it first before running this funciton"
		return 1
	fi

	cn=$(openssl x509 -noout -subject -in "${cert_file}" | grep -Eo 'CN\s+=\s+.*$' | cut -d '=' -f 2 | xargs)
	ret=$?
	if ((ret != 0)) ; then 
		echo "Cannot get the common name from the cert"
		return 1
	fi

	mosquitto_sub -c -d -h $fqdn -p 8883 -i "$cn" -u "$hostname/$cn/?api-version=2021-04-12" -t "devices/$cn/messages/devicebound/#" --capath "/etc/ssl/certs/" -V mqttv311 -q 1 --cert "$cert_file" --key "$key_file" --tls-version tlsv1.2 --insecure
}

# Function: show_cert
# Description: Test connect to IoT Hub MQTT by using the X509 cert based device
# Options:
#	%1: X.509 certificate file path
# Return: 0 if success, non-0 otherwise
function show_cert() {
	local OPTIND
	if ! cmd_exist openssl ; then
		echo "Openssl cannot be found, please install it first before running this function"
		return 1
	fi

	if (( $# != 1)); then
		echo "Usage: show_cert cert_file_path"
		return 1
	fi

	if [ ! -r "$1" ]; then
		echo "Cert file doesn't exist or the cert file doesn't have read permission."
		return 1
	fi

	openssl x509 -in "$1" -noout -text
}

# Function: gen_rsa_cert
# Description: Generate the RSA2048 certificate
# Options:
#	-n: The certificate and key name (w/o extension)
#	-c: The CA cert for signing the cert
#	-k: The CA key for signing the cert
#	-d: The certificate valid days
#	-e: The X.509 V3 extension attribute configuraiton file
# Return: 0 if success, non-0 otherwise
function gen_rsa_cert() {
	local OPTIND
	local days=180
	while getopts ":n:c:k:e:d:" opt; do
		case $opt in
			n) local name=$OPTARG ;;
			c) local ca_file=$OPTARG ;;
			k) local ca_key=$OPTARG ;;
			e) local ext_file=$OPTARG ;;
			d) days=$OPTARG ;;
			*) echo "Unknown option: $opt" ; return 1 ;;
		esac
	done

	local key_len=2048
	local ret

	if ! cmd_exist openssl ; then
		echo "Openssl cannot be found, please install it first before running this function"
		return 1
	fi

	openssl genrsa -out "${name}.pem" $ken_len
	ret=$?
	if (( $ret != 0 )); then
		echo "Error: cannot generate the RSA key file"
		return 1;
	fi

	openssl req -new -key "${name}.pem" -out "${name}.csr"
	ret=$?
	if (( $ret != 0 )); then
		echo "Error: cannot generate the CSR file"
		return 1;
	fi

	openssl x509 -req -CA "${ca_file}" -CAkey "${ca_key}" -in "${name}.csr" -out "${name}.crt" -days $days -CAcreateserial -extfile "${ext_file}"
	ret=$?
	if (( $ret != 0 )); then
		echo "Error: cannot generate the certificate"
		return 1;
	fi

	echo "Success: generated the certificate file: ${name}.crt"

	return 0 
}

function show_certs_in_pem() {
	local OPIND
	while getopts ":c" opt; do
		case $opt in
			c) local bundle_pem_file=$OPTARG ;;
			*) echo "Unkown option: $opt" ; return 1;;
		esac
	done

	if ! cmd_exist openssl ; then
		echo "Openssl cannot be found, please install it first before running this function"
		return 1
	fi

	openssl crl2pkcs7 -nocrl -certfile "$bundle_pem_file" | openssl pkcs7 -print_certs -text -noout
	ret=$?
	if (( $et != 0 )); then
		echo "Error: cannot show the certification details in the bundle."
		return 1;
	fi

	return 0
}