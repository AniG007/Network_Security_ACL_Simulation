#FOR STANDARD ACL

f1 = open(r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\file1.txt", "r")
f2 = open(r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\file2.txt", "r")

f1_content = f1.read()
f2_content = f2.read()

f1_content_array = f1_content.splitlines()  # Splitting the lines as array elements
f2_content_array = f2_content.splitlines()  # Splitting the lines as array elements

mask_counter = 0
ip_counter = 0
#these 2 counters are used to track if an ip matches with the acl rule according to the mask

for i in f2_content_array:
    ip_packet_status = False #To check if the packet needs to be dropped by deny all
    input_ip = i.split(".") #splitting the input ip in an array

    for x in f1_content_array:
        if x.__contains__("deny") or x.__contains__("permit"): #only permit or deny are needed to filter packets, hence this condition
            acl_line = x.split(" ") #splitting the acl condition into separate array elements

            #checking if the keyword any is present in the acl rules and processing it accordingly
            if acl_line.__contains__("any"):
                acl_ip = ['0','0','0','0']
                acl_mask = ['255','255','255','255']
            else:
                acl_ip = acl_line[3].split(".") #the third array element is the acl_ip by default in all the cases
                acl_mask = acl_line[4].split(".") #the fourth array element is the mask in all the cases
            for j in range(4):
                if acl_mask[j] == "0":
                    mask_counter += 1
                    if acl_ip[j] == input_ip[j]:
                        ip_counter += 1

            if mask_counter == ip_counter:
                mask_counter = 0
                ip_counter = 0
                ip_packet_status = True # setting this to true so that deny all won't be performed for the specific ip
                if acl_line[2] == "deny":
                    f3 = open(
                        r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\outputfile.txt",
                        "a")
                    f3.write("Packet From " + i + " denied\n")
                    f3.close()
                else:
                    f3 = open(
                        r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\outputfile.txt",
                        "a")
                    f3.write("Packet From " + i + " permitted\n")
                    f3.close()
                break
            else:
                mask_counter = 0 # resetting the counters for the next ip in the iteration
                ip_counter = 0

    if not ip_packet_status: # deny_all scenario
        f3 = open(
            r"C:\\Users\sonyg\Documents\Network Security\Assignments\Assignment3\Input_Files\outputfile.txt",
            "a")
        f3.write("Packet From " + i + " denied\n")
        f3.close()

f1.close()
f2.close()
