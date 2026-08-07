SELECT *
FROM {{ source('iceberg', 'detections') }}
