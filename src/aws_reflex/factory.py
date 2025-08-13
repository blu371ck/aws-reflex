HANDLER_MAPPING = {
    "Backdoor:EC2/C2Activity.B": "<REPLACE_WITH_CLASS_IMPORT>",
    "Recon:EC2/PortProbeUnprotectedPort": "<REPLACE_WITH_CLASS_IMPORT>"
}

def get_handler(finding):
    """
    Factory function to return the appropriate handler instance for a
    given finding.
    """
    finding_type = finding.get('Type')
    HandlerClass = HANDLER_MAPPING.get(finding_type)

    if HandlerClass:
        return HandlerClass(finding)
    
    return None