def fragment_message(message, chunk_size: int = 20):
    chunks = []
    total = (len(message) + chunk_size - 1) // chunk_size
    for i in range(total):
        part = message[i*chunk_size : (i+1)*chunk_size]
        chunk = f"{part}|{total}|{i}"
        chunks.append(chunk.encode('utf8'))
    return chunks