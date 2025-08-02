def fragment_message(message, port, chunk_size):
    chunks = []
    total = (len(message) + chunk_size - 1) // chunk_size
    for i in range(total):
        part = message[i*chunk_size : (i+1)*chunk_size]
        chunk = f"{part}|{total}|{i}|{port}"
        chunks.append(chunk.encode('utf8'))
    return chunks