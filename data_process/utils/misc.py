from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

def langchain_to_openai_messages(langchain_messages):
    role_map = {
        HumanMessage: "user",
        AIMessage: "assistant",
        SystemMessage: "system",
    }
    openai_messages = []
    for msg in langchain_messages:
        role = role_map.get(type(msg))
        if role is None:
            raise ValueError(f"Unsupported message type: {type(msg)}")
        openai_messages.append({
            "role": role,
            "content": msg.content
        })
    return openai_messages