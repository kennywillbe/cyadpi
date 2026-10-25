# docs/demo.gif is generated from this file:
#
#   sudo env VHS_NO_SANDBOX=true vhs docs/demo.tape
#   sudo chown "$USER" docs/demo.gif
#
# Under sudo because the take runs `sudo cyadpi` for real: vhs drives its own
# terminal, where nobody can type a password, and as root sudo asks for none.
# It is a live recording, so it only shows a block on a network that actually
# blocks discord.com. cyadpi has to be installed; the hidden part turns it off
# first and back on at the end, leaving the machine as it was.

Output docs/demo.gif

Set Shell bash
Set FontFamily "Menlo"
Set FontSize 20
Set LineHeight 1.2
Set Width 1200
Set Height 820
Set Padding 26
Set Margin 36
Set MarginFill "#5b4b8a"
Set WindowBar Colorful
Set WindowBarSize 40
Set BorderRadius 12
Set TypingSpeed 45ms
Set Framerate 24
Set Theme "Catppuccin Mocha"

Hide
# A green arrow prompt, and the comments typed below dimmed by the shell's own
# echo: they narrate the take without a voice-over.
# The log is emptied so `cyadpi status` shows this take, not the history of
# the machine it was recorded on.
Type `export PS1='\[\e[1;32m\]❯\[\e[0m\] ' && cyadpi off >/dev/null 2>&1; : > /var/log/cyadpi.log; cd /tmp && clear`
Enter
Sleep 1s
Show

Sleep 700ms
Type "# discord.com, cyadpi off"
Enter
Sleep 400ms
Type "curl -sSI https://discord.com | head -1"
Sleep 500ms
Enter
Wait+Screen@15s /curl: \(/
Sleep 2.2s

Type "sudo cyadpi"
Sleep 500ms
Enter
Wait+Screen@10s /starts at every boot/
Sleep 1.8s

Type "# same request, cyadpi on"
Enter
Sleep 400ms
Type "curl -sSI https://discord.com | head -1"
Sleep 500ms
Enter
Wait+Screen@15s /HTTP\/2 200/
Sleep 2.5s

Type "cyadpi status"
Sleep 500ms
Enter
Sleep 2.8s

Type "sudo cyadpi off"
Sleep 500ms
Enter
Wait+Screen@20s /until the next boot/
Sleep 3s

Hide
Type "cyadpi >/dev/null 2>&1"
Enter
Sleep 3s
