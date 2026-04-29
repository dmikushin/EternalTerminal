#compdef et

_et() {
    local -a simple_flags
    local -a flags

    simple_flags=(
        '-N[Do not create a terminal]'
        '-c[Run command on connect and exit]:command'
        '-f[Forward ssh-agent socket]'
        '-g[Allow remote hosts to connect to local forwarded ports]'
        '-h[Print help]'
        '-p[Remote machine etserver port]:port'
        '-L[Local port forwarding (ssh-style)]:forward'
        '-R[Remote port forwarding (ssh-style)]:forward'
        '-u[Username]:username'
        '-v[Enable verbose logging]:level'
        '-x[kill all old sessions belonging to the user]'
        '-e[Used with -c to not exit after command is run]'
        '-k[Client keepalive duration in seconds]:seconds'
        '-l[Base directory for log files]:directory:_files -/'
    )
    flags=(
        '--help[Print help]'
        '--version[Print version]'
        '--verbose[Enable verbose logging]:level'
        '--command[Run command on connect and exit]:command'
        '--forward-ssh-agent[Forward ssh-agent socket]'
        '--gateway-ports[Allow remote hosts to connect to local forwarded ports]'
        '--exit-on-forward-failure[Exit if any -L/-R forward fails]'
        '--host[Remote host name]:host:_hosts'
        '--jumphost[jumphost between localhost and destination]:host:_hosts'
        '--jport[Jumphost machine port]:port'
        '--kill-other-sessions[kill all old sessions belonging to the user]'
        '--logtostdout[Write log to stdout]'
        '--no-terminal[Do not create a terminal]'
        '--local-forward[Local port forwarding (ssh-style)]:forward'
        '--remote-forward[Remote port forwarding (ssh-style)]:forward'
        '--port[Remote machine etserver port]:port'
        '--silent[Disable logging]'
        '--serverfifo[communicate to etserver on matching fifo name]:fifo'
        '--ssh-socket[The ssh-agent socket to forward]:socket'
        '--username[Username]:username'
        '--noexit[Used with -c to not exit after command is run]'
        '--jserverfifo[communicate to jumphost on matching fifo name]:fifo'
        '--macserver[Set when connecting to an macOS server]'
        '--keepalive[Client keepalive duration in seconds]:seconds'
        '--logdir[Base directory for log files]:directory:_files -/'
        '--telemetry[Allow et to anonymously send errors]'
        '--terminal-path[Path to etterminal on server side]:path:_files'
        '--ssh-option[Options to pass down to `ssh -o`]:option'
    )

    _arguments -s \
        $simple_flags \
        $flags \
        '*:host:_hosts'
}
