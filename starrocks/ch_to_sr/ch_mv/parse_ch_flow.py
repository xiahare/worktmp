"""
Run command:

python3 parse_ch_flow.py mv_sqls


"""

import re
import os
from collections import defaultdict

def clean_table_name(name):
    """Clean table name by removing schema prefix and special characters"""
    if name.startswith('siem.'):
        name = name[5:]
    if '$' in name:
        name = name.split('$')[0]
    return name.strip('`"\' ')

def extract_flow_info(content):
    """Extract data flow information from SQL content"""
    # Extract target table name
    target = None
    is_mv = 'MATERIALIZED VIEW' in content.upper()
    log_type = None
    
    # Check for log type conditions
    log_type_match = re.search(r'_devlogtype\s*=\s*(\d+)', content)
    if log_type_match:
        log_type = log_type_match.group(1)
    
    if is_mv:
        # For materialized views - extract TO clause
        to_match = re.search(r'TO\s+([^\s;]+)', content, re.IGNORECASE)
        if to_match:
            target = clean_table_name(to_match.group(1))
    else:
        # For regular tables - extract CREATE TABLE
        create_match = re.search(r'CREATE TABLE IF NOT EXISTS ([^\s(]+)', content, re.IGNORECASE)
        if create_match:
            target = clean_table_name(create_match.group(1))
    
    if not target:
        return None
    
    # Extract source tables from FROM clauses
    sources = set()
    from_matches = re.finditer(
        r'FROM\s+(?:[^(]*?)(?:\([^)]*\))*\s*([^\s,);]+)', 
        content, 
        re.IGNORECASE
    )
    
    for match in from_matches:
        source = clean_table_name(match.group(1))
        if source and not any(s in source for s in ['$', '(', '=', 'SELECT']):
            sources.add(source)
    
    return (target, sources, log_type) if sources else None

def build_flow_graph(directory):
    """Build complete data flow graph"""
    flow_graph = defaultdict(set)
    table_map = {}  # Maps table names to files
    file_targets = {}  # Maps files to their target tables
    log_type_map = {}  # Maps files to their log type conditions
    
    # First pass: Collect all tables and materialized views
    for filename in os.listdir(directory):
        if filename.endswith('.sql'):
            with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
                content = f.read()
                info = extract_flow_info(content)
                if info:
                    target, _, log_type = info
                    table_map[target] = filename
                    file_targets[filename] = target
                    if log_type:
                        log_type_map[filename] = log_type
    
    # Second pass: Build flow relationships
    for filename in os.listdir(directory):
        if filename.endswith('.sql'):
            with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
                content = f.read()
                info = extract_flow_info(content)
                if info:
                    target, sources, _ = info
                    
                    # For materialized views, use the TO clause target
                    if filename in file_targets:
                        target = file_targets[filename]
                    
                    for source in sources:
                        # Find the file corresponding to the source table
                        source_file = None
                        if source in table_map:
                            source_file = table_map[source]
                        elif source + '.sql' in file_targets:
                            source_file = source + '.sql'
                        elif source in ['elog_sp', 'ulog_sp', 'tlog_sp']:
                            # Raw log tables
                            flow_graph[(source, None)].add((filename, log_type_map.get(filename)))
                            continue
                        
                        if source_file:
                            flow_graph[(source_file, None)].add((filename, log_type_map.get(filename)))
    
    return flow_graph

def print_flow(flow_graph):
    """Print the data flow graph"""
    # Find all starting points (tables/files that aren't referenced by others)
    all_targets = set()
    for sources in flow_graph.values():
        for (target, _) in sources:
            all_targets.add(target)
    
    starters = set()
    for (source, _) in flow_graph.keys():
        if source not in all_targets:
            starters.add((source, None))
    
    # Ensure raw log tables are included as starting points
    for log_table in ['elog_sp', 'ulog_sp', 'tlog_sp']:
        if (log_table, None) in flow_graph:
            starters.add((log_table, None))
    
    if not starters:
        print("No data flow relationships found.")
        return
    
    print("Data Flow Graph:")
    
    visited = set()
    
    def print_node(node, log_type=None, indent=0):
        node_key = (node, log_type)
        if node_key in visited:
            return
        visited.add(node_key)
        
        display_name = os.path.splitext(node)[0] if node.endswith('.sql') else node
        prefix = "    " * indent
        
        # Handle log type display before the arrow
        if log_type:
            prefix += f"({log_type}) "
        prefix += "-> "
        
        print(prefix + display_name)
        
        for (child, child_log_type) in sorted(flow_graph.get((node, None), set())):
            print_node(child, child_log_type, indent + 1)
    
    for (start, _) in sorted(starters):
        print_node(start)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python parse_ch_flow.py <sql_directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist")
        sys.exit(1)
    
    flow_graph = build_flow_graph(directory)
    print_flow(flow_graph)