@ ECHO off

:begin
echo.
echo	 #######################################
echo	 #         HASHCAT BAT SCRIPT          #
echo	 # 1) DICTIONARY ATTACK                #
echo	 # 2) BRUTE-FORCE ATTACK               #
echo	 # 3) RULE-BASED ATTACK                #
echo	 #######################################
echo.
set /p mychoice="Enter your number: "
echo.

if "%mychoice%" == "1" (
	echo.
	echo You picked DICTIONARY ATTACK
	echo.
	set /p capname1="Please tell me your .cap file name: "
	set /p dicname="Please tell me your Dictionary you want: "
	goto dic
)


if "%mychoice%" == "2" (
	echo.
	echo You picked BRUTE-FORCE ATTACK 
	echo.
	set /p capname2="Please tell me your .cap file name: "
	echo.
	echo 	Example  ?d?d?d?d?d?d?d?d    
	echo 	?l = abcdefghijklmnopqrstuvwxyz
	echo 	?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
	echo 	?d = 0123456789
	echo 	?a = ?l?u?d?s
	echo 	?s =  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	echo.
	echo 	YOU MUST INPUT STRING NOW!
	set /p brutename="Please tell me your brute string: "
	goto brute
)




if "%mychoice%" == "3" (
	echo.
	echo You picked RULE-BASED ATTACK
	echo Place rule in rule Directory
	echo.
	set /p capname3="Please tell me your .cap file name: "
	echo 	YOU MUST INPUT RULE NAME!
	set /p rule="Please tell me your rule name: "	
	set /p file="Please tell me your File name: "
	goto rule
)


:dic
cudaHashcat64.exe -m 2500 %capname1% %dicname%
pause

:brute
cudaHashcat64.exe -m 2500 -a3 %capname2% %brutename%
pause

:rule
cudaHashcat64.exe -m 2500 -r rules/%rule% %capname3% %file%
pause

:end
echo HOPE IT WORKED !!!
pause
