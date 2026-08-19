package ghostguard

default allow = false

deny if {
    input.tool_name == "exec"
}

deny if {
    input.tool_name == "shell"
}

deny if {
    input.tool_name == "bash"
}

deny if {
    input.tool_name == "file_write"
}

deny if {
    input.tool_name == "create_file"
}

deny if {
    input.tool_name == "delete_file"
}

deny if {
    input.tool_name == "http_request"
    not startswith(input.arguments.url, "https://api.openai.com")
    not startswith(input.arguments.url, "https://api.anthropic.com")
}

log if {
    input.tool_name == "query_database"
}

log if {
    input.tool_name == "search_web"
}

allow if {
    input.tool_name == "get_weather"
}

allow if {
    input.tool_name == "search_web"
}

allow if {
    input.tool_name == "read_file"
}
