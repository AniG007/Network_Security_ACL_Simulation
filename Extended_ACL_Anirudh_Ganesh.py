#FOR EXTENDED ACL

f1 = open(r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\file1.txt", "r")
f2 = open(r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\file2.txt", "r")

f1_content = f1.read()
f2_content = f2.read()

f1_content_array = f1_content.splitlines()  # Splitting the lines as array elements
f2_content_array = f2_content.splitlines()  # Splitting the lines as array elements

mask_counter = 0
ip_counter = 0

#these counters are used to track if an ip matches with the acl rule according to the mask

# loop for iterating through the input ip's
for i in f2_content_array:
    ip_packet_status = False #To check if the packet needs to be dropped by deny all
    input_ips = i.split(" ") #splitting the input in an array

    source_ip = input_ips[0].split(".")
    destn_ip = input_ips[1].split(".")

    port = input_ips[2]

    # loop for iterating through the acl rules
    for x in f1_content_array:

        if x.__contains__("deny") or x.__contains__("permit"): #checking for boundary conditions
            acl_rule = x.split(" ")
            protocol = acl_rule[3]

            # These condition are to check if the keyword any is present in a line and the line is processed accordingly
            if acl_rule[4] == "any" and acl_rule[5] == "any":
                acl_source = ['0', '0', '0', '0']
                source_mask = ['255', '255', '255', '255']
                acl_destn = ['0', '0', '0', '0']
                destn_mask = ['255', '255', '255', '255']

            elif acl_rule[4] == "any":
                acl_source = ['0', '0', '0', '0']
                source_mask = ['255', '255', '255', '255']
                acl_destn = acl_rule[5].split(".")
                destn_mask = acl_rule[6].split(".")

            elif acl_rule[6] == "any":
                acl_source = acl_rule[4].split(".")
                source_mask = acl_rule[5].split(".")

                acl_destn = ['0', '0', '0', '0']
                destn_mask = ['255', '255', '255', '255']
            else:
                acl_source = acl_rule[4].split(".")
                acl_destn = acl_rule[6].split(".")

                source_mask = acl_rule[5].split(".")
                destn_mask = acl_rule[7].split(".")

            action = acl_rule[2]

            for j in range(4):
                if source_mask[j] == "0":
                    mask_counter += 1
                    if acl_source[j] == source_ip[j]:
                        ip_counter += 1

                if destn_mask[j] == "0":
                    mask_counter += 1
                    if acl_destn[j] == destn_ip[j]:
                        ip_counter += 1

            if mask_counter == ip_counter:
                # check if the source and destn ip match according to the masks, if yes, then check the ports,
                if x.__contains__("range"): # checking for boundary conditions
                    arr_length = acl_rule.__len__()  # to get the port numbers from the end of the line
                    port_rule = acl_rule[arr_length-2]
                    ports = acl_rule[arr_length-1].split("-")

                    if port <= ports[1] and port >= ports[0]:

                        mask_counter = 0
                        ip_counter = 0
                        ip_packet_status = True  # setting this to true so that deny all won't be performed for the specific ip
                        if(action == "deny"):
                            f3 = open(
                                r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                                "a")
                            f3.write("Packet From " + input_ips[0] + " to " + input_ips[1] + " on port " + port + " denied\n")
                            f3.close()
                        else:
                            f3 = open(
                                r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                                "a")
                            f3.write("Packet From " + input_ips[0] + " to " + input_ips[1] + " on port " + port + " permitted\n")
                            f3.close()
                        break

                elif x.__contains__("eq"):
                    arr_length = acl_rule.__len__()  # to get the port numbers from the end of the line
                    port_rule = acl_rule[arr_length - 2]
                    ports = acl_rule[arr_length - 1].split("-")

                    if ports.__contains__(port):#[0]): # if ports are inclusive are per acl rule
                        mask_counter = 0
                        ip_counter = 0
                        ip_packet_status = True  # setting this to true so that deny all won't be performed for the specific ip
                        if (action == "deny"):
                            f3 = open(
                                r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                                "a")
                            f3.write("Packet From " + input_ips[0] + " to " + input_ips[
                                1] + " on port " + port + " denied\n")
                            f3.close()
                        else:
                            f3 = open(
                                r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                                "a")
                            f3.write("Packet From " + input_ips[0] + " to " + input_ips[
                                1] + " on port " + port + " permitted\n")
                            f3.close()
                        break
                else: # if ports are not mentioned
                    mask_counter = 0
                    ip_counter = 0
                    ip_packet_status = True
                    if (action == "deny"):
                        f3 = open(
                            r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                            "a")
                        f3.write("Packet From " + input_ips[0] + " to " + input_ips[1] + " on port " + port + " denied\n")
                        f3.close()
                    else:
                        f3 = open(
                            r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
                            "a")
                        f3.write("Packet From " + input_ips[0] + " to " + input_ips[1] + " on port " + port + " permitted\n")
                        f3.close()
                    break

            else: # if the ip's do not match
                mask_counter = 0
                ip_counter = 0

    if not ip_packet_status:  # deny_all scenario
        f3 = open(
            r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\extended_acl\outputfile.txt",
            "a")
        f3.write("Packet From " + input_ips[0] + " to " + input_ips[1] + " on port " + port + " denied\n")
        f3.close()

f1.close()
f2.close()
