# `recreate_facet_table.sh` - Facet Table Management Script

This script is designed to manage the `facet_result` and `facet_process` tables in your data catalog. It provides functionality to either list the current hash partition settings for all storage groups or to completely recreate these tables for one or more specified storage groups.

## Features

-   **List All Settings:** If run without any parameters, the script will iterate through all `storage_id`s registered in Consul and display the current hash partition settings for their respective `__<storage_id>_facet_result` tables.
-   **Recreate Tables:** If one or more `storage_id`s are provided as parameters, the script will perform a full recreation process for each one.
-   **Comprehensive Recreation Process:** The recreation process includes:
    1.  Capturing and displaying the old hash partition settings.
    2.  Dropping the existing `facet_result` and `facet_process` tables.
    3.  Refreshing the hash partition configuration via an API call.
    4.  Triggering a long-running asynchronous task to recreate the tables.
    5.  Polling for the completion of the recreation task.
    6.  Clearing the Redis cache.
    7.  Verifying the final table creation and displaying the new hash partition settings.

## Usage

### No Parameters

To list the hash partition settings for all `storage_id`s, run the script without any arguments:

```bash
./recreate_facet_table.sh
```

### One Parameter

To recreate the facet tables for a single `storage_id`, provide it as an argument:

```bash
./recreate_facet_table.sh <storage_id>
```

### Multiple Parameters

To recreate the facet tables for multiple `storage_id`s, provide them as a comma-separated list:

```bash
./recreate_facet_table.sh <storage_id_1>,<storage_id_2>,<storage_id_3>
```
