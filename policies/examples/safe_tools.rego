package ghostguard

default allow = false

# Block code execution tools
deny if {
    input.tool_name == "exec"
}

deny if {
    input.tool_name == "shell"
}

deny if {
    input.tool_name == "bash"
}

# Block file system writes
deny if {
    input.tool_name == "file_write"
}

deny if {
    input.tool_name == "create_file"
}

deny if {
    input.tool_name == "delete_file"
}

# Allow common safe tools
allow if {
    input.tool_name == "get_weather"
}

allow if {
    input.tool_name == "search_web"
}

allow if {
    input.tool_name == "read_file"
}

allow if {
    input.tool_name == "query_database"
}

# Log database queries for audit
log if {
    input.tool_name == "query_database"
}
