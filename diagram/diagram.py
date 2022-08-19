#!/usr/bin/env python3

from diagrams import Diagram
from diagrams import Cluster
from diagrams.aws.network import VPC
from diagrams.aws.general import InternetGateway
from diagrams.aws.network import RouteTable
from diagrams.aws.network import NATGateway
from diagrams.aws.network import PrivateSubnet
from diagrams.aws.network import PublicSubnet
from diagrams.aws.compute import EC2ElasticIpAddress
from diagrams.aws.network import RouteTable
from diagrams.aws.network import Route53
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.aws.network import ALB
from diagrams.aws.compute import AutoScaling
from diagrams.aws.database import RDSPostgresqlInstance
from diagrams.aws.compute import EC2Instance
from diagrams.onprem.network import Internet
from diagrams.aws.database import ElasticacheForRedis

graph_attr_diagram = {
    "fontsize": "35",
    "arrowsize": "1.5"
}

graph_attr_clusters = {
    "fontsize": "27",
    "arrowsize": "1.5"
}

graph_attr_nodes = {
    "fontsize": "25",
    "arrowsize": "1.5"
}

edge_attr_diagram = {
    "fontsize": "25"
}

with Diagram("TFE Active-Active ASG LB", filename="diagram", show = False, direction="TB", edge_attr=edge_attr_diagram, graph_attr=graph_attr_diagram, node_attr=graph_attr_nodes):
    internet1 = Internet("Internet")
    with Cluster("AWS", graph_attr=graph_attr_clusters):
        s3_data = SimpleStorageServiceS3Bucket(" \nData")
        route53 = Route53(" \nRoute53")
        with Cluster("VPC", graph_attr=graph_attr_clusters):
            igw = InternetGateway("Internet Gateway")
            rt_private_1 = RouteTable(" \n\n \nRoute\ntable\nprivate-1")
            rt_public_1 = RouteTable(" \n\n \nRoute\ntable\npublic-1")
            rt_private_2 = RouteTable(" \n\n \nRoute\ntable\nprivate-2")
            rt_public_2 = RouteTable(" \n\n \nRoute\ntable\npublic-2")
            subnet_private_1 = PrivateSubnet(" \n\n \nPrivate\nsubnet\nprivate-1")
            subnet_private_2 = PrivateSubnet(" \n\n \nPrivate\nsubnet\nprivate-2")
            subnet_public_1 = PublicSubnet(" \n\n \nPublic\nsubnet\npublic-1")
            subnet_public_2 = PublicSubnet(" \n\n \nPublic\nsubnet\npublic-2")
            alb = ALB(" \n\n \nApplication\n Load\n Balancer")
            rdsdn = RDSPostgresqlInstance(" \nRDS\n Postgresql DB")
            redis = ElasticacheForRedis(" \nElasticache\n Redis")
            autoscale = AutoScaling(" \nASG")
            internet1 >> igw
            route53 >> alb
            with Cluster("Availability Zone 1", graph_attr=graph_attr_clusters):
                ngw1 = NATGateway(" \n\n \nNAT\n Gateway 1")
                ec2_1 = EC2Instance(" \nTFE Instance 1")
                with Cluster("Private subnet 1", graph_attr=graph_attr_clusters):
                    igw >> rt_private_1 >> subnet_private_1 >> ngw1 >> ec2_1 >> [rdsdn, redis]
                with Cluster("Public subnet 1", graph_attr=graph_attr_clusters):
                    igw >> rt_public_1 >> subnet_public_1 >> alb >> autoscale >> ec2_1 >> [s3_data]
            with Cluster("Availability Zone 2", graph_attr=graph_attr_clusters):
                ngw2 = NATGateway(" \n\n \nNAT\n  Gateway 2")
                ec2_2 = EC2Instance("TFE Instance 2")
                with Cluster("Private subnet 2", graph_attr=graph_attr_clusters):
                    igw >> rt_private_2 >> subnet_private_2 >> ngw2 >> ec2_2 >> [rdsdn, redis]
                with Cluster("Public subnet 2", graph_attr=graph_attr_clusters):
                    igw >> rt_public_2 >> subnet_public_2 >> alb >> autoscale >> ec2_2 >> [s3_data]
