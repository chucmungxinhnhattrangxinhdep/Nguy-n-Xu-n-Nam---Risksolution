/**
 ***************************************************************************
 * Copyright (C) 2007, Roberto Perdisci, Davide Ariu                       *
 * roberto.perdisci@gmail.com, davide.ariu@diee.unica.it                   *
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

package pocad.network;

import java.util.*;
import java.io.*;

import pocad.featureClustering.*;
import pocad.svm.svm_model;
import pocad.utils.*;

import jpcap.packet.*;

import jpcap.*;
import org.eclipse.jetty.client.HttpRequest;


public class PacketClassifier implements PacketReceiver {
	
	public enum CombinationRule {
		MAJ_VOTING, AVG_PROB, PROD_PROB, MIN_PROB, MAX_PROB
	};

	public static final int MIN_NUM_OF_GRAMS = 1;

	public static final String NIC_NAME_PREFIX = "NIC_";

	public static final int NIC_SNAPLEN = 2000;

	public static final int NIC_TIMEOUT = 20;

	protected DirectoryHandler directoryHandler;

	private TestSVMHandler testSVMHandler;

	private svm_model[] models;

	private FeatureClustersMap[] featureClustersMaps;

	private int[] nuValues;

	private int maxNu;

	private int payloadLength = -1;

	private ClassificationResults results;
	
	protected double packetSamplingRatio = 1;
	
	protected long totalPcapFilePackets = 0;

	protected long totalPacketCounter = 0;

	protected long testedPackets = 0;
	
	private Map<CombinationRule, Double> testCombinationRuleSet = new HashMap<CombinationRule, Double>();

	/**
	 * 
	 * @param directoryHandler
	 * @param payloadLength
	 *            only the packets having a payload of specified length will be
	 *            considered for classification.<br>
	 *            (-1 = all the lengths)
	 */
	public PacketClassifier(DirectoryHandler directoryHandler) {

		ClusteringConfiguration clustConfig = new ClusteringConfiguration(
				directoryHandler.getClusterConfigFile().getAbsolutePath());

		this.directoryHandler = directoryHandler;
		this.payloadLength = clustConfig.payloadLength;

		testSVMHandler = new TestSVMHandler(directoryHandler);
		File[] mapsFileList = this.directoryHandler.getFcMapsDir().listFiles();
		Arrays.sort(mapsFileList);
		featureClustersMaps = new FeatureClustersMap[mapsFileList.length];
		nuValues = new int[mapsFileList.length];
		try {
			System.err.print("Tải models...");
			models = testSVMHandler.loadModels();
			//System.err.println("ok");
			for (int i = 0; i < mapsFileList.length; i++) {
				FileInputStream in = new FileInputStream(mapsFileList[i]);
				ObjectInputStream os = new ObjectInputStream(in);
				String trainingFile = ((String) os.readObject());
				nuValues[i] = ((Integer) os.readObject()).intValue();
				//System.err.print("loading map" + mapsFileList[i].getName() + " - Nu = " + nuValues[i] + "... ");
				featureClustersMaps[i] = (FeatureClustersMap) os.readObject();
				//System.err.println("ok");
				os.close();
			}
			maxNu = maxNu(nuValues);
		} catch (IOException e) {
			System.err.println("Exception in PacketReceiverClass::test-> " + e);
			System.exit(1);
		} catch (ClassNotFoundException e) {
			System.err.println("Exception in PacketReceiverClass::test-> " + e);
			System.exit(1);
		}
	}

	public static byte[] extractPayload(Packet packet) {

                
                
		if (packet == null)
			return null;

		byte[] payload = null;

		try {
			IPPacket ipp = (IPPacket) packet;
			if (ipp == null)
				return null;

			if (ipp.protocol == IPPacket.IPPROTO_TCP) {
				TCPPacket tcpPacket = (TCPPacket) packet;
				payload = tcpPacket.data;
			} else if (ipp.protocol == IPPacket.IPPROTO_UDP) {
				UDPPacket udpPacket = (UDPPacket) packet;
				payload = udpPacket.data;
			} else {
				//System.err.println("CANNOT PROCESS PACKET (PROTOCOL !in {TCP,UDP})");
				// System.exit(1);
			}
		} catch (ClassCastException e) {
			//System.err.println("CANNOT PROCESS PACKET (NOT AN *IP* PACKET)");
		} catch (Exception e) {
			System.err
					.println("Exception in PacketClassifier.extractPayload : "
							+ e);
		}

		return payload;
	}

	public void receivePacket(Packet packet) {

		try {
			totalPacketCounter++;

			byte[] payload = extractPayload(packet);

			if (payload != null && payload.length > 0 && Math.random()<packetSamplingRatio) {
				testedPackets++;
				testPacket(packet, totalPacketCounter);
			}

			/* DEBUG *
			if (totalPacketCounter % 1000 == 0)
				System.err.print("--->" + totalPacketCounter + "("
						+ testedPackets + ") - ");
			*/

		} catch (Exception e) {
			System.err.println("Exception in PacketClassifier.receivePacket : "
					+ e);
		}
	}

	public static double[] computePairFrequency(byte[] data, int nu,
			FeatureClustersMap fcMap) {
		return DataSetFactory.computePairFrequency(data, nu, fcMap);
	}

	protected TestPacketResults testPacket(Packet packet, long packetID) {

		TestPacketResults packetResults = null;

		byte[] payload = extractPayload(packet);

		if (payload != null
				&& (payload.length == this.payloadLength || this.payloadLength == -1)) {
			results.incrementAnalyzedPackets();

			if ((payload.length - maxNu - 1) >= MIN_NUM_OF_GRAMS) {
				results.incrementTestedPackets();
				
				try {

					packetResults = new TestPacketResults();

					for (int i = 0; i < nuValues.length; i++) {

						double[] pairFreq = computePairFrequency(payload,
								nuValues[i], featureClustersMaps[i]);
						int k = featureClustersMaps[i].getNumberOfClusters();

						// sum of decisions for Majority Voting
						packetResults.decisions += TestSVMHandler.predictLabel(
								pairFreq, models[i]);

						double p = TestSVMHandler.predictProbability(pairFreq,
								models[i], k);

						packetResults.probabilityAvg += p
								/ (double) nuValues.length;

						packetResults.probabilityProd *= Math.pow(p,
								1 / (double) nuValues.length);

						if (p < packetResults.probabilityMin)
							packetResults.probabilityMin = p;

						if (p > packetResults.probabilityMax)
							packetResults.probabilityMax = p;

					}

					if (testCombinationRuleSet != null) {
						boolean detected = false;
						StringBuffer combRulesReport = new StringBuffer();
						if (testCombinationRuleSet.keySet().contains(
								CombinationRule.MAJ_VOTING)
								&& packetResults.decisions < testCombinationRuleSet
										.get(CombinationRule.MAJ_VOTING)) {
							detected = true;
							results.incrementNumDetectedAttacksMajVoting();
							combRulesReport.append("  MajVoting (d="
									+ packetResults.decisions + ")  ");
						}
						if (testCombinationRuleSet.keySet().contains(
								CombinationRule.AVG_PROB)
								&& packetResults.probabilityAvg < testCombinationRuleSet
										.get(CombinationRule.AVG_PROB)) {
							detected = true;
							results.incrementNumDetectedAttacksAvgProb();
							combRulesReport.append("  AvgProb (p="
									+ packetResults.probabilityAvg + ")  ");
						}
						if (testCombinationRuleSet.keySet().contains(
								CombinationRule.PROD_PROB)
								&& packetResults.probabilityProd < testCombinationRuleSet
										.get(CombinationRule.PROD_PROB)) {
							detected = true;
							results.incrementNumDetectedAttacksProdProb();
							combRulesReport.append("  ProdProb (p="
									+ packetResults.probabilityProd + ")  ");
						}
						if (testCombinationRuleSet.keySet().contains(
								CombinationRule.MIN_PROB)
								&& packetResults.probabilityMin < testCombinationRuleSet
										.get(CombinationRule.MIN_PROB)) {
							detected = true;
							results.incrementNumDetectedAttacksMinProb();
							combRulesReport.append("  MinProb (p="
									+ packetResults.probabilityMin + ")  ");
						}
						if (testCombinationRuleSet.keySet().contains(
								CombinationRule.MAX_PROB)
								&& packetResults.probabilityMax < testCombinationRuleSet
										.get(CombinationRule.MAX_PROB)) {
							detected = true;
							results.incrementNumDetectedAttacksMaxProb();
							combRulesReport.append("  MaxProb (p="
									+ packetResults.probabilityMax + ")  ");
						}
						
						if (detected)
							printAlertInfo(packet, packetID, combRulesReport
									.toString());
					}

				} catch (NullPointerException e) {
					System.err.println("The reason is " + e.getCause());
				} catch (Exception e) {
					System.err.println(e + " : " + e.getCause());
				}
			}
		}

		return packetResults;
	}

	public ClassificationResults test(String fileName, String filter,
			Map<CombinationRule, Double> thresholds, int numOfPackets) {

		testCombinationRuleSet = thresholds;
				
		try {

			results = new ClassificationResults();

			if (!fileName.startsWith(NIC_NAME_PREFIX)) {
				PcapPacketCounter pcount = new PcapPacketCounter();
				totalPcapFilePackets = pcount.countPackets(fileName,filter);
				if(numOfPackets == -1)
					packetSamplingRatio = 1;
				else {
					packetSamplingRatio = numOfPackets/(double)totalPcapFilePackets;
					numOfPackets = -1;
				}
			}
			
			JpcapCaptor captor = null;
			if (fileName.startsWith(NIC_NAME_PREFIX)) {
				NetworkInterface[] devicesList = JpcapCaptor.getDeviceList();
				String nicName = fileName.substring(NIC_NAME_PREFIX.length());
				int nicID = -1;
				for (int i = 0; i < devicesList.length; i++) {
					if (devicesList[i].name.equals(nicName))
						nicID = i;
				}
				if (nicID >= 0)
					captor = JpcapCaptor.openDevice(devicesList[1],
							NIC_SNAPLEN, true, NIC_TIMEOUT);
				else {
					System.err.println("Network interface " + nicName
							+ "cannot be found!");
					System.err.println("Availabel NICs:");
					for(int k=0; k<devicesList.length; k++) {
						System.out.println("- " + devicesList[k]);
					}
					System.exit(1);
				}
			} else {
				captor = JpcapCaptor.openFile(fileName);
			}

			if (filter != null)
				captor.setFilter(filter, true);
			// Start reading packets
			captor.loopPacket(numOfPackets, this);
		}

		catch (IOException e) {
			System.err.println("Exception in openDevice " + e);
			System.exit(1);
		}

		return results;
	}

	private void printAlertInfo(Packet packet, long packetID,
			String combRulesReport) {
		try {
			IPPacket ipp = (IPPacket) packet;
			int srcPort = -1;
			int dstPort = -1;
			int length = 0;
			String srcAddress = null;
			String dstAddress = null;
			Date date = new Date();

			if (ipp.protocol == IPPacket.IPPROTO_TCP) {
				TCPPacket tcpPacket = (TCPPacket) packet;
				srcPort = tcpPacket.src_port;
				dstPort = tcpPacket.dst_port;
				srcAddress = tcpPacket.src_ip.toString();
				dstAddress = tcpPacket.dst_ip.toString();
				length = tcpPacket.data.length;
				System.out.print(packetID + " ~ " + date + "\t[TCP]\t");
			} else if (ipp.protocol == IPPacket.IPPROTO_UDP) {
				UDPPacket udpPacket = (UDPPacket) packet;
				srcPort = udpPacket.src_port;
				dstPort = udpPacket.dst_port;
				srcAddress = udpPacket.src_ip.toString();
				dstAddress = udpPacket.dst_ip.toString();
				length = udpPacket.data.length;
				System.out.print(packetID + " ~ " + date + "\t[UDP]\t");
			}
			System.out.print("SRC: " + srcAddress + ":" + srcPort + "\t");
			System.out.print("DST: " + dstAddress + ":" + dstPort + "\t");
			System.out.print("LEN: " + length + "\t");
			System.out.println("[" + combRulesReport + "]");

		} catch (ClassCastException e) {
			//System.err.println("CANNOT PROCESS PACKET (NOT AN *IP* PACKET)");
		}
	}

	private int maxNu(int[] v) {
		int max = v[0];
		for (int i = 1; i < v.length; i++) {
			if (max < v[i])
				max = v[i];
		}

		return max;
	}
}
