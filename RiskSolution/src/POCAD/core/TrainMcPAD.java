/**
 ***************************************************************************
 * Copyright (C) 2007, Roberto Perdisci                                    *
 * roberto.perdisci@gmail.com                                              *
 *                                                                         *
 * Distributed under the GNU Public License                                *
 * http://www.gnu.org/licenses/gpl.txt                                     *   
 *                                                                         *
 * This program is free software; you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation; either version 2 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *             
 * This program is distributed in the hope that it will be useful,         *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 ***************************************************************************
 */

package pocad.core;

import java.util.HashMap;
import java.util.Map;

import pocad.network.ThresholdFactory;
import pocad.network.PacketClassifier.CombinationRule;
import pocad.utils.DirectoryHandler;
import pocad.utils.SVMClassifierHandler;
import gnu.getopt.Getopt;

public class TrainMcPAD {

	public static void main(String[] args) {

		String rootDirectory = null;
		double falsePositiveRate = -1;
		int maxNumOfValidationPackets = -1;
		
		Getopt g = new Getopt(TestMcPAD.class.getSimpleName(), args,
		"r:t:d:f:c:n:");
		
		int c;
		while ((c = g.getopt()) != -1) {
			switch (c) {

			case 'r':
				rootDirectory = g.getOptarg();
				System.out.println("-r " + rootDirectory);
				break;
				
			case 'f':
				falsePositiveRate = Double.parseDouble(g.getOptarg());
				System.out.println("-f " + falsePositiveRate);
				break;

			case 'n':
				maxNumOfValidationPackets = Integer.parseInt(g.getOptarg());
				System.out.println("-n " + maxNumOfValidationPackets);
				break;

			default:
				printUsage();
				System.exit(1);
				break;
			}
		}
		
		if(rootDirectory==null || falsePositiveRate<0 || maxNumOfValidationPackets<0) {
			printUsage();
			System.exit(1);
		}
		
		DirectoryHandler directoryHandler = new DirectoryHandler(rootDirectory);
		
		SVMClassifierHandler svm = new SVMClassifierHandler(directoryHandler);
		System.out.println("Computing feature clusters...");
		svm.generateFeatureClusters();
		System.out.println("Generating training datasets...");
		svm.generateTrainDatasets();
		System.out.println("Training one-class SVM models...");
		svm.generateModels();
		
		System.out.println("Computing detection threshods...");
		Map<CombinationRule, Double> thresholds = new HashMap<CombinationRule, Double>();
		ThresholdFactory thFactory = new ThresholdFactory(directoryHandler);
		thresholds = thFactory.getThresholds(maxNumOfValidationPackets, falsePositiveRate);
		ThresholdFactory.printThresholds(thresholds);
		System.out.println("Saving threshods...");
		thFactory.saveThreshodls(thresholds,"thresholds.obj");
		
		System.out.println();
		System.out.println("done!");
	}
	
	private static void printUsage() {
		System.out
		.println(TestMcPAD.class.getSimpleName()
				+ " -r root_dir -f desired_fpr -n max_validation_packets");
	}

}
