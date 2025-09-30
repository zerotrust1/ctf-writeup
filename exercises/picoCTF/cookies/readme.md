# Cookies
Description:
Who doesn't love cookies? Try to figure out the best one. http://mercury.picoctf.net:64944/

# How to solve
Access the url sites it'll return you to this ui <br> <br>
<img width="859" height="595" alt="image" src="https://github.com/user-attachments/assets/4076a540-bc64-4ce2-9cad-c6e9159b3e8f" />
<br>
press ctrl + shift + i and open application tab to see the cookies <br> <br>
<img width="618" height="936" alt="image" src="https://github.com/user-attachments/assets/30cde391-5544-43f5-80c7-cb8ccf042bb7" /> 
<br>
The value is -1. Then I try to search for snickerdoodle highlighted in search bar. 
it's redirected to site.com/check endpoint. And now the cookies changed to 0 instead previously -1.
Then we look again in the description. "figure the best one" So from there I start thinking maybe we can try to change the value of the cookies until we found the right value

So I change the cookies to 2 <img width="1920" height="956" alt="image" src="https://github.com/user-attachments/assets/7f271d1d-3008-4334-a637-6bd658396dd4" />
See how the cookies name changaed, then I increase the number to 3,4,5, etc until I found the flag which on the value of 18
<img width="1917" height="754" alt="image" src="https://github.com/user-attachments/assets/1b2ca263-ee48-48e2-aa76-95306adb9c79" />
picoCTF{3v3ry1_l0v3s_c00k135_cc9110ba}

# what we learn
So from here we learn that cookies is on our computer we can change it with everything we want.
