# import python modules
import os
import time
import logging
import multiprocessing

# import django modules

# import third party modules
from rq.decorators import job
from redis import Redis

# import project specific model classes
from config.models import Origin

# import app specific utility classes

# import app specific utility functions
from .utils import packet_chunk
from .utils import run_capture
from .utils import read_pcap


pythos_redis_conn = Redis()

@job('discovery_queue', connection=pythos_redis_conn)
def discovery_task(origin_uuid="",
                   offline=False,
                   interface="",
                   duration=0,
                   filepath="",
                   origin_description=""
                   ):

    logging.basicConfig(filename="/tmp/pythos_debug.log", level=logging.DEBUG)

    m = multiprocessing.Manager()
    packets = m.Queue()

    multiprocessing.log_to_stderr(logging.INFO)

    num_processes = os.cpu_count()
    if not num_processes:
        num_processes = 2

    pool = multiprocessing.Pool(processes=num_processes, maxtasksperchild=1)

    if offline:
        current_origin = Origin.objects.create(name="PCAP " + filepath,
                                               description=origin_description,
                                               sensor_flag=True,
                                               plant_flag=False
                                               )
        discovery_process = multiprocessing.Process(target=read_pcap,
                                                    args=(filepath,
                                                          packets
                                                          )
                                                    )
        logging.info("Starting to read pcap file: " + filepath)
    else:
        try:
            current_origin = Origin.objects.get(uuid=origin_uuid)
        except:
            logging.error("Could not find specified origin: " + origin_uuid +
                          " Aborting."
                          )
            return

        discovery_process = multiprocessing.Process(target=run_capture,
                                                    args=(interface,
                                                          duration,
                                                          packets
                                                          )
                                                    )
        logging.info("Starting live capture on: " + interface)

    discovery_process.start()

    logging.info("Starting " + str(num_processes) + " worker processes.")

    while discovery_process.is_alive() or not packets.empty():
        num_packets = packets.qsize()
        chunk_size = max(num_packets//num_processes, 10000)

        logging.debug(str(num_packets) + " packets in queue.")

        if num_packets > chunk_size:
            chunk = m.Queue()
            for i in range(chunk_size):
                chunk.put(packets.get())
            logging.debug("Processing chunk with size: " + str(chunk_size))
            pool.apply_async(packet_chunk, args=(chunk,
                                                 current_origin,
                                                 packets
                                                 )
                             )

        elif not discovery_process.is_alive():
            logging.debug("Processing last chunk.")
            pool.apply(packet_chunk, args=(packets, current_origin, packets))

        time.sleep(10)

    pool.close()
    pool.join()

    if offline:
        logging.info("Pcap " + filepath + " has been processed successfully.")
    else:
        logging.info("Live capture on " + interface + " has been completed.")
