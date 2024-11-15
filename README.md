# twmailer - basic - project
For FH Technikum Wien Informatics (BIF) Semester 3 - Subject verts

## Server
```bash
./server 8000 mailspool/
```

## Client
```bash
./client 127.0.0.1 8000
```

## Testing
### Login
```
// Command before Login
>> LIST
<< ERR

// Blacklisting
>> LOGIN
<< OK
>> if99b000
<< OK
Enter password: 
<< ERR
>> LOGIN
<< OK
>> if99b000
<< OK
Enter password: 
<< ERR
>> LOGIN
<< OK
>> if99b000
<< OK
Enter password: 
<< ERR
>> LOGIN
<< OK
>> if99b000
<< ERR
// No password was asked anymore
// Login with correct creds
>> LOGIN
<< OK
>> if24b001
<< OK
Enter password: 
<< OK
>> LIST
<< 0
```

### Send
```
>> SEND
<< OK
>> if24b002
<< OK
>> Test Subject
<< OK
>> Line1
>> Line2
>> !
>> Line4
>> End
>> .
<< OK
```

### List
```
>> LIST
<< 5
Test Subject.txt
testmsg1.txt
subj1.txt
largemsg.txt
subj2.txt
```

### Read
```
>> READ
<< OK
>> 1
<< OK
# Message by if24b002:

Line1
Line2
!
Line4
End
.
>> READ
<< OK
>> 99
<< ERR
>> READ
<< OK
>> -1 
<< ERR
>> READ
<< OK
>> nan
<< ERR
```

### Del
```
>> DEL
<< OK
>> 99
<< ERR
>> DEL
<< OK
>> -1
<< ERR
>> DEL
<< OK
>> 1
<< OK
```

