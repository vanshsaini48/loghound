"""Merge multiple log files into a time-ordered event stream."""
import heapq
from pathlib import Path
from .detector import detect_and_parse


def merge_event_streams(file_paths, format_override=None, show_progress=False):
    """
    Merge events from multiple log files, maintaining time order.
    
    Uses a min-heap to merge streams from multiple files while keeping
    the output sorted by timestamp (required for windowed detections).
    
    Args:
        file_paths: list of Path objects
        format_override: optional format name
        show_progress: whether to show progress for large files
    
    Yields:
        Event objects in time order across all files
    """
    # Open all files and create event iterators
    iterators = []
    for i, file_path in enumerate(file_paths):
        parser_name, events_iter = detect_and_parse(
            file_path, 
            format_override=format_override,
            show_progress=show_progress
        )
        iterators.append((file_path, events_iter))
    
    # Use a heap to merge streams: (timestamp, sequence, file_index, event)
    # sequence ensures stable ordering when timestamps are equal
    heap = []
    sequence = 0
    
    # Prime the heap with the first event from each file
    for file_idx, (file_path, events_iter) in enumerate(iterators):
        try:
            event = next(events_iter)
            heapq.heappush(heap, (event.timestamp, sequence, file_idx, event))
            sequence += 1
        except StopIteration:
            # File is empty
            pass
    
    # Extract from heap and refill
    while heap:
        timestamp, _, file_idx, event = heapq.heappop(heap)
        
        # Try to get the next event from the same file
        file_path, events_iter = iterators[file_idx]
        try:
            next_event = next(events_iter)
            heapq.heappush(heap, (next_event.timestamp, sequence, file_idx, next_event))
            sequence += 1
        except StopIteration:
            # File exhausted
            pass
        
        yield event
